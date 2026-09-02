//! `collector-wifi` — the `wifi` collector: Wi-Fi air quality (RSSI, noise floor,
//! negotiated transmit rate, PHY mode, channel) mapped into a [`types::WifiSample`].
//!
//! The daemon can already say the gateway stopped answering. This collector is
//! what lets it say why the *air* stopped carrying: in a saturated channel the
//! link stays associated and the signal looks fine while the transmit window
//! never arrives — invisible to the ping, the bound TCP probe and the CoreCapture
//! verdict alike.
//!
//! Holds the [`WifiFacts`] port trait (implemented by the `macos` crate over
//! CoreWLAN), the pure [`build_wifi_sample`] mapping, static [`META`], and the
//! [`WifiCollector`] that plugs into `collector_core::Collector`.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{META, WifiCollector};
pub use facts::{WifiFacts, WifiRead, WifiReading};
pub use sample::build_wifi_sample;
