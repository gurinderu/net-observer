//! The `wifi` collector's port trait: air-quality facts read from the OS behind a
//! trait boundary so the mapping logic stays unit-testable with fakes. The real
//! adapter (CoreWLAN through `objc2`) lives in the `macos` crate.

use collector_core::Readiness;

/// One associated radio's raw reading. Every field is independently optional:
/// the OS may decline any single value while still being associated, and a
/// declined field is `None` inside an otherwise valid reading — never a reason to
/// throw the whole tick away.
///
/// RSSI and the noise floor are kept as the raw pair; the SNR margin is derived
/// downstream in [`crate::build_wifi_sample`], not here, so the derivation can be
/// revisited without losing what was measured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WifiReading {
    /// Received signal strength, dBm (negative).
    pub rssi_dbm: Option<i32>,
    /// Noise floor, dBm (negative).
    pub noise_dbm: Option<i32>,
    /// Negotiated transmit rate, Mbps.
    pub tx_rate_mbps: Option<f64>,
    /// Active PHY mode label ("11a"/"11b"/"11g"/"11n"/"11ac"/"11ax").
    pub phy_mode: Option<String>,
    /// Channel number (e.g. 48).
    pub channel: Option<i32>,
    /// Channel width in MHz (20/40/80/160).
    pub channel_width_mhz: Option<i32>,
    /// Band label ("2ghz"/"5ghz"/"6ghz").
    pub channel_band: Option<String>,
}

/// What the OS answered for one Wi-Fi tick.
///
/// The two arms are the whole vocabulary the mapping needs: either the radio was
/// associated and there is a reading, or the probe could not run and says why.
/// "Could not run" is not silence — it becomes a `SKIP` sample carrying the
/// reason, every tick, for as long as it lasts.
#[derive(Debug, Clone, PartialEq)]
pub enum WifiRead {
    /// Associated: a reading, whose individual fields may still be `None`.
    Associated(WifiReading),
    /// The probe could not run (no Wi-Fi interface, radio powered off, not
    /// associated, CoreWLAN unavailable). The string is the operator-facing
    /// reason recorded on the SKIP sample.
    Unavailable(String),
}

/// Wi-Fi air-quality facts gathered from the OS.
///
/// Native `async fn` in a trait (no `async-trait` macro); the daemon drives it
/// via static dispatch, so the trait is intentionally not dyn-compatible.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait WifiFacts: Send + Sync {
    /// Read the radio once. Never fails: an unusable radio is a
    /// [`WifiRead::Unavailable`] carrying its reason, not an `Err` and never a
    /// missing tick.
    async fn read(&self) -> WifiRead;
    /// Runtime capability probe: Ready iff a Wi-Fi interface exists here/now,
    /// else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
