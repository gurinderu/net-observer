//! Wi-Fi air quality read from **CoreWLAN** through `objc2`.
//!
//! # Why a typed framework call and not a command's output
//!
//! `wdutil` prints freeform text that changes silently between macOS releases,
//! and `system_profiler SPAirPortDataType` both spawns a process and performs a
//! *scan* of the surrounding networks — an observer that stirs the air in order
//! to measure it is the wrong instrument. CoreWLAN's accessors are passive
//! (they read the driver's own association statistics, sending nothing) and a
//! typed call breaks loudly at compile time rather than quietly at parse time.
//! That is the trade this module buys.
//!
//! # The surface
//!
//! There is no CoreWLAN binding crate in this workspace, so the three classes are
//! declared by hand against the runtime:
//!
//! * `CWWiFiClient` — `+sharedWiFiClient`, `-interface`
//! * `CWInterface` — `-powerOn`, `-activePHYMode`, `-rssiValue`,
//!   `-noiseMeasurement`, `-transmitRate`, `-wlanChannel`
//! * `CWChannel` — `-channelNumber`, `-channelWidth`, `-channelBand`
//!
//! MCS index and spatial-stream count are NOT here: CoreWLAN does not expose
//! them, and the only source is `wdutil` text. CCA / channel utilisation is out
//! of scope for the same reason.
//!
//! SSID and BSSID are deliberately not read. macOS gates them behind Location
//! Services, which a LaunchDaemon cannot obtain — root `wdutil` returns
//! `SSID : <redacted>` on this machine while RSSI comes through fine. The SSID is
//! collected by the `link` collector instead.

use collector_core::Readiness;
use collector_wifi::{WifiFacts, WifiRead, WifiReading};
use objc2::ffi::NSInteger;
use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool};

// CoreWLAN is not linked by anything else in this workspace; without this the
// `CWWiFiClient` class is simply absent from the runtime at lookup time.
#[link(name = "CoreWLAN", kind = "framework")]
unsafe extern "C" {}

/// `CWPHYMode`. `kCWPHYModeNone == 0` is what an unassociated interface reports,
/// which is how "the radio is up but joined to nothing" is detected.
const PHY_MODE_NONE: NSInteger = 0;

/// Map `CWPHYMode` to the label recorded in the sample. An unknown future mode
/// keeps its numeric identity rather than being flattened into a wrong name.
fn phy_mode_label(mode: NSInteger) -> Option<String> {
    Some(match mode {
        PHY_MODE_NONE => return None,
        1 => "11a".to_string(),
        2 => "11b".to_string(),
        3 => "11g".to_string(),
        4 => "11n".to_string(),
        5 => "11ac".to_string(),
        6 => "11ax".to_string(),
        other => format!("phy{other}"),
    })
}

/// Map `CWChannelWidth` to MHz. `kCWChannelWidthUnknown == 0` yields `None` — the
/// OS declined the value, and a declined value is never guessed.
fn channel_width_mhz(width: NSInteger) -> Option<i32> {
    match width {
        1 => Some(20),
        2 => Some(40),
        3 => Some(80),
        4 => Some(160),
        _ => None,
    }
}

/// Map `CWChannelBand` to a label. `kCWChannelBandUnknown == 0` yields `None`.
fn channel_band_label(band: NSInteger) -> Option<String> {
    match band {
        1 => Some("2ghz".to_string()),
        2 => Some("5ghz".to_string()),
        3 => Some("6ghz".to_string()),
        _ => None,
    }
}

/// A dBm reading, or `None` when the driver declined it. CoreWLAN reports `0` for
/// "no value": a real association is never at 0 dBm for either signal or noise,
/// so 0 is the sentinel and not a measurement.
fn dbm(value: NSInteger) -> Option<i32> {
    if value == 0 { None } else { Some(value as i32) }
}

/// Fetch `CWWiFiClient`'s current interface, or `None` when CoreWLAN is absent or
/// the machine has no Wi-Fi hardware.
///
/// Synchronous and self-contained on purpose: no `Retained` ever crosses an
/// `await`, which is what keeps the collector's future `Send`.
fn current_interface() -> Option<Retained<AnyObject>> {
    // `AnyClass::get` returns `None` rather than panicking (unlike `class!`), so a
    // machine without CoreWLAN degrades to a SKIP instead of taking the daemon down.
    let cls = AnyClass::get(c"CWWiFiClient")?;
    // SAFETY: `+[CWWiFiClient sharedWiFiClient]` takes no arguments and returns a
    // (non-null, autoreleased) `CWWiFiClient *`. Typing the return as
    // `Option<Retained<AnyObject>>` makes `objc2` apply the +0 → +1 ownership
    // transfer, so the object is retained here and released on drop; it is
    // therefore valid for as long as this binding lives, with no autorelease pool
    // required.
    let client: Option<Retained<AnyObject>> = unsafe { msg_send![cls, sharedWiFiClient] };
    let client = client?;
    // SAFETY: `-[CWWiFiClient interface]` takes no arguments and returns a
    // NULLABLE, autoreleased `CWInterface *` (nil when the host has no Wi-Fi
    // hardware) — matched by the `Option<Retained<_>>` return, which handles both
    // the null case and the ownership transfer. `client` is a live `CWWiFiClient`
    // by construction above.
    unsafe { msg_send![&*client, interface] }
}

/// Read the radio once. Pure syscall-shaped work; see [`current_interface`] for
/// why this is deliberately synchronous.
fn read_interface() -> WifiRead {
    let Some(iface) = current_interface() else {
        return WifiRead::Unavailable("no Wi-Fi interface".to_string());
    };

    // SAFETY (all message sends below): `iface` is a live `CWInterface` obtained
    // from `-[CWWiFiClient interface]` above and retained for the duration of this
    // function. Every selector is a documented, argument-less CoreWLAN property
    // accessor whose declared return type matches the Rust type it is read into:
    // `-powerOn` → `BOOL`, `-activePHYMode`/`-rssiValue`/`-noiseMeasurement` →
    // `NSInteger`, `-transmitRate` → `double`, `-wlanChannel` → a nullable
    // `CWChannel *` (typed as `Option<Retained<_>>`). None of them take arguments
    // or transfer ownership beyond what `Retained` accounts for.
    let powered: Bool = unsafe { msg_send![&*iface, powerOn] };
    if !powered.as_bool() {
        return WifiRead::Unavailable("Wi-Fi radio powered off".to_string());
    }

    let phy_mode: NSInteger = unsafe { msg_send![&*iface, activePHYMode] };
    if phy_mode == PHY_MODE_NONE {
        // The radio is on but joined to nothing (Ethernet, a wired-only session).
        return WifiRead::Unavailable("not associated".to_string());
    }

    let rssi: NSInteger = unsafe { msg_send![&*iface, rssiValue] };
    let noise: NSInteger = unsafe { msg_send![&*iface, noiseMeasurement] };
    let tx_rate: f64 = unsafe { msg_send![&*iface, transmitRate] };
    let channel: Option<Retained<AnyObject>> = unsafe { msg_send![&*iface, wlanChannel] };

    let (number, width, band) = match channel {
        // SAFETY: `ch` is a live `CWChannel` from `-wlanChannel`; `-channelNumber`,
        // `-channelWidth` and `-channelBand` are its argument-less `NSInteger`
        // (enum-typed) accessors.
        Some(ch) => unsafe {
            let number: NSInteger = msg_send![&*ch, channelNumber];
            let width: NSInteger = msg_send![&*ch, channelWidth];
            let band: NSInteger = msg_send![&*ch, channelBand];
            (Some(number as i32), width, band)
        },
        None => (None, 0, 0),
    };

    WifiRead::Associated(WifiReading {
        rssi_dbm: dbm(rssi),
        noise_dbm: dbm(noise),
        // A negotiated rate of 0 is CoreWLAN's "no value", not a real 0 Mbps link.
        tx_rate_mbps: (tx_rate > 0.0).then_some(tx_rate),
        phy_mode: phy_mode_label(phy_mode),
        channel: number,
        channel_width_mhz: channel_width_mhz(width),
        channel_band: channel_band_label(band),
    })
}

/// macOS implementation of [`WifiFacts`] backed by CoreWLAN.
#[derive(Debug, Default, Clone, Copy)]
pub struct CoreWlanFacts;

impl CoreWlanFacts {
    /// Create a new CoreWLAN reader. Stateless — the shared `CWWiFiClient` is
    /// fetched per read, so a Wi-Fi interface that appears later is picked up
    /// without restarting the daemon.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl WifiFacts for CoreWlanFacts {
    async fn read(&self) -> WifiRead {
        // CoreWLAN's accessors read cached driver state and return immediately,
        // so the read runs inline — no `spawn_blocking`. Crucially it contains no
        // `await`, so no non-`Send` `Retained` is ever held across a yield point.
        read_interface()
    }

    async fn preflight(&self) -> Readiness {
        // Readiness is about the *probe*, not the association: a machine with a
        // Wi-Fi interface that happens to be off the air is Ready, and its ticks
        // report SKIP with the reason. Only a host with no Wi-Fi at all (or no
        // CoreWLAN) is Unavailable — for that host the reason never changes and a
        // per-tick row would say nothing new.
        if current_interface().is_some() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("no Wi-Fi interface (CoreWLAN)".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phy_modes_map_to_their_labels() {
        assert_eq!(phy_mode_label(0), None);
        assert_eq!(phy_mode_label(4).as_deref(), Some("11n"));
        assert_eq!(phy_mode_label(5).as_deref(), Some("11ac"));
        assert_eq!(phy_mode_label(6).as_deref(), Some("11ax"));
        // A mode this build does not know keeps its numeric identity rather than
        // being reported as a mode it is not.
        assert_eq!(phy_mode_label(99).as_deref(), Some("phy99"));
    }

    #[test]
    fn channel_width_and_band_decline_unknowns() {
        assert_eq!(channel_width_mhz(0), None);
        assert_eq!(channel_width_mhz(1), Some(20));
        assert_eq!(channel_width_mhz(4), Some(160));
        assert_eq!(channel_band_label(0), None);
        assert_eq!(channel_band_label(2).as_deref(), Some("5ghz"));
    }

    /// CoreWLAN's `0` means "no value"; a real association is never at 0 dBm.
    #[test]
    fn zero_dbm_is_a_declined_value_not_a_measurement() {
        assert_eq!(dbm(0), None);
        assert_eq!(dbm(-53), Some(-53));
        assert_eq!(dbm(-96), Some(-96));
    }

    /// Reads the real radio on this host. Asserts only what holds on ANY machine
    /// — Wi-Fi, Ethernet or CI runner — so it can never be a flake: the read
    /// always answers, an association always carries a PHY mode, and a SKIP always
    /// carries a reason.
    #[tokio::test]
    async fn reading_the_real_radio_always_answers() {
        match CoreWlanFacts::new().read().await {
            WifiRead::Associated(r) => {
                assert!(r.phy_mode.is_some(), "an association has a PHY mode");
                if let Some(rssi) = r.rssi_dbm {
                    assert!(rssi < 0, "RSSI is a negative dBm value: {rssi}");
                }
                if let Some(noise) = r.noise_dbm {
                    assert!(noise < 0, "the noise floor is negative dBm: {noise}");
                }
            }
            WifiRead::Unavailable(reason) => {
                assert!(!reason.is_empty(), "a SKIP must say why");
            }
        }
    }
}
