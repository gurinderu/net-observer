//! The air map: the foreign access points this machine's radio can hear, and
//! the *hypothesis* that one of them sits on top of our own channel.
//!
//! Two limits shape every type here, and neither is a gap to be filled later
//! (realm net-observer, nodes #47 and #48):
//!
//! * **No BSSID.** The system report carries none, so two access points on the
//!   same channel are indistinguishable between scans. An observation is part of
//!   a *slice*, never an entity with a lifetime — unlike a neighbour, a foreign
//!   AP cannot be followed through time.
//! * **No channel occupancy.** macOS hands out no CCA / airtime figure to
//!   anybody, so "that AP is stealing my air" is not measurable here. What *is*
//!   computable is how far its band overlaps ours and how loud it arrives — a
//!   hypothesis, carried by [`ChannelOverlapHypothesis`], whose name says so and
//!   which deliberately has no field pretending to be measured airtime.

use serde::{Deserialize, Serialize};

use crate::verdict::AirVerdict;

/// One foreign access point as heard in a single scan.
///
/// Every field is independently optional: the report may decline any one of them
/// while still listing the AP, and a declined field is `None` inside an otherwise
/// valid observation. There is deliberately no name and no BSSID field — the
/// report redacts the SSID and never carries a BSSID at all.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AirObservation {
    /// Channel number (e.g. 44).
    pub channel: Option<i32>,
    /// Band label, normalised lowercase: "2ghz" / "5ghz" / "6ghz".
    pub channel_band: Option<String>,
    /// Channel width in MHz (20/40/80/160).
    pub channel_width_mhz: Option<i32>,
    /// PHY mode label as reported ("802.11a/n/ac/ax").
    pub phy_mode: Option<String>,
    /// Security mode label as reported, with the platform's
    /// `spairport_security_mode_` prefix stripped ("wpa2_personal_mixed").
    pub security: Option<String>,
    /// Received signal strength, dBm (negative).
    pub rssi_dbm: Option<i32>,
    /// Noise floor as measured for this AP, dBm (negative).
    pub noise_dbm: Option<i32>,
}

/// One scan of the radio environment.
///
/// `air == Skip` means the scan could not run at all (radio off, the report
/// failed, the report had no wireless section) and `reason` says which — a SKIP
/// row every period, never silence and never an empty `aps` list, which would
/// read as "the air is clear".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirSample {
    pub ts_us: i64,
    pub air: AirVerdict,
    /// Why the scan could not run. `Some` iff `air == Skip`.
    pub reason: Option<String>,
    /// The foreign access points heard. Meaningful only when `air == Ok`: an
    /// empty list under `Ok` is the real reading "nobody else is audible", which
    /// is why the SKIP case must never be represented the same way.
    pub aps: Vec<AirObservation>,
}

/// The three Wi-Fi bands the report distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    TwoGhz,
    FiveGhz,
    SixGhz,
}

impl Band {
    /// Parse a band label, case-insensitively, in either the platform's spelling
    /// ("5GHz") or the store's normalised one ("5ghz").
    #[must_use]
    pub fn parse(s: &str) -> Option<Band> {
        match s.trim().to_ascii_lowercase().as_str() {
            "2ghz" | "2.4ghz" => Some(Band::TwoGhz),
            "5ghz" => Some(Band::FiveGhz),
            "6ghz" => Some(Band::SixGhz),
            _ => None,
        }
    }

    /// The normalised lowercase label written to the store.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Band::TwoGhz => "2ghz",
            Band::FiveGhz => "5ghz",
            Band::SixGhz => "6ghz",
        }
    }

    /// Centre frequency in MHz of `channel` in this band, for the 5/6 GHz bands
    /// whose channels are laid out as `base + 5 * n`. `None` for 2.4 GHz, whose
    /// overlap is computed from channel numbers instead (see
    /// [`overlap_hypothesis`]).
    fn centre_mhz(self, channel: i32) -> Option<i32> {
        match self {
            Band::TwoGhz => None,
            Band::FiveGhz => Some(5000 + 5 * channel),
            Band::SixGhz => Some(5950 + 5 * channel),
        }
    }
}

/// Where a radio sits: a channel in a band, occupying a width.
///
/// `width_assumed` records that the width was not reported and 20 MHz was taken
/// as the floor — the overlap computed from it is weaker evidence, and
/// [`overlap_hypothesis`] downgrades its confidence for exactly that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSpan {
    pub channel: i32,
    pub band: Band,
    pub width_mhz: i32,
    pub width_assumed: bool,
}

impl ChannelSpan {
    /// Build a span from the optional columns the store keeps, or `None` when
    /// there is not even a channel and a band to place the radio with.
    ///
    /// A missing width becomes 20 MHz — the narrowest real channel, so the
    /// assumption can only *understate* an overlap — flagged `width_assumed`.
    #[must_use]
    pub fn new(channel: Option<i32>, band: Option<&str>, width_mhz: Option<i32>) -> Option<Self> {
        let channel = channel?;
        let band = Band::parse(band?)?;
        let (width_mhz, width_assumed) = match width_mhz {
            Some(w) if w > 0 => (w, false),
            _ => (20, true),
        };
        Some(ChannelSpan {
            channel,
            band,
            width_mhz,
            width_assumed,
        })
    }
}

/// How strongly a [`ChannelOverlapHypothesis`] is held.
///
/// Never rises above `High`, and `High` is still a hypothesis: it says the two
/// bands demonstrably intersect and the foreign signal's strength is known — not
/// that any air was measured being taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapConfidence {
    /// At least one width had to be assumed, so the span is a guess.
    Low,
    /// Both widths were reported, but the foreign signal strength was not — how
    /// loud the overlap arrives is unknown.
    Medium,
    /// Both widths and the foreign RSSI were reported.
    High,
}

/// A hypothesis about a foreign AP sitting on our channel.
///
/// **Not a measurement of interference.** macOS reports no channel occupancy to
/// anyone, so what can be computed is the fraction of our channel its band
/// covers plus how loud it arrives. There is deliberately no airtime field: a
/// number that looked measured would be the one thing this type exists to
/// prevent (realm net-observer, node #48).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ChannelOverlapHypothesis {
    /// Fraction of the narrower of the two channels that the two spans share,
    /// `0.0` (disjoint or a different band) to `1.0` (fully covered).
    pub overlap: f64,
    /// The foreign AP's signal strength, dBm, when it was reported.
    pub rssi_dbm: Option<i32>,
    /// How strongly the hypothesis is held.
    pub confidence: OverlapConfidence,
}

impl ChannelOverlapHypothesis {
    /// Ordering key for "who is most likely treading on our band": stronger
    /// overlap first, and among equal overlaps the louder signal first.
    ///
    /// A *ranking*, not a score — two ordered fields rather than one composite
    /// number, because a composite would read as a measured quantity.
    #[must_use]
    pub fn rank_key(&self) -> (i64, i32) {
        // Overlap is scaled and truncated so the key is totally ordered (f64 is
        // not `Ord`); 1e6 keeps far more resolution than the inputs carry.
        let scaled = (self.overlap * 1e6) as i64;
        (scaled, self.rssi_dbm.unwrap_or(i32::MIN))
    }
}

/// Compute the overlap hypothesis between our own channel and a foreign one.
///
/// * **2.4 GHz** channels are 5 MHz apart and 20 MHz wide, so any two whose
///   numbers differ by less than 5 overlap; the fraction is `(5 - |Δ|) / 5`.
///   The number rule is used for the whole band, including a rare 40 MHz AP —
///   the report's channel numbering is what is trustworthy there.
/// * **5 / 6 GHz** channels are placed by centre frequency (`5000 + 5·n`,
///   `5950 + 5·n`) and the spans are intersected: the fraction is the shared
///   width over the narrower of the two channels.
/// * **Different bands** never overlap.
#[must_use]
pub fn overlap_hypothesis(
    own: &ChannelSpan,
    other: &ChannelSpan,
    other_rssi_dbm: Option<i32>,
) -> ChannelOverlapHypothesis {
    let overlap = if own.band != other.band {
        0.0
    } else if own.band == Band::TwoGhz {
        let delta = (own.channel - other.channel).abs();
        f64::from((5 - delta).max(0)) / 5.0
    } else {
        match (
            own.band.centre_mhz(own.channel),
            other.band.centre_mhz(other.channel),
        ) {
            (Some(a), Some(b)) => {
                // Halves are doubled throughout so odd widths stay exact in
                // integer arithmetic.
                let (a_lo, a_hi) = (2 * a - own.width_mhz, 2 * a + own.width_mhz);
                let (b_lo, b_hi) = (2 * b - other.width_mhz, 2 * b + other.width_mhz);
                let shared = (a_hi.min(b_hi) - a_lo.max(b_lo)).max(0);
                let narrower = own.width_mhz.min(other.width_mhz) * 2;
                if narrower <= 0 {
                    0.0
                } else {
                    (f64::from(shared) / f64::from(narrower)).min(1.0)
                }
            }
            _ => 0.0,
        }
    };
    let confidence = if own.width_assumed || other.width_assumed {
        OverlapConfidence::Low
    } else if other_rssi_dbm.is_none() {
        OverlapConfidence::Medium
    } else {
        OverlapConfidence::High
    };
    ChannelOverlapHypothesis {
        overlap,
        rssi_dbm: other_rssi_dbm,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(channel: i32, band: Band, width: i32) -> ChannelSpan {
        ChannelSpan {
            channel,
            band,
            width_mhz: width,
            width_assumed: false,
        }
    }

    #[test]
    fn band_parses_both_spellings_and_rejects_junk() {
        assert_eq!(Band::parse("5GHz"), Some(Band::FiveGhz));
        assert_eq!(Band::parse("5ghz"), Some(Band::FiveGhz));
        assert_eq!(Band::parse(" 2GHz "), Some(Band::TwoGhz));
        assert_eq!(Band::parse("6GHz"), Some(Band::SixGhz));
        assert_eq!(Band::parse("60GHz"), None);
        assert_eq!(Band::parse(""), None);
    }

    #[test]
    fn span_needs_a_channel_and_a_band_but_assumes_a_width() {
        assert_eq!(ChannelSpan::new(None, Some("5ghz"), Some(80)), None);
        assert_eq!(ChannelSpan::new(Some(44), None, Some(80)), None);
        assert_eq!(ChannelSpan::new(Some(44), Some("nonsense"), Some(80)), None);
        let s = ChannelSpan::new(Some(44), Some("5ghz"), None).unwrap();
        assert_eq!(s.width_mhz, 20);
        assert!(s.width_assumed);
        // A nonsensical width is treated as absent, not trusted.
        let s = ChannelSpan::new(Some(44), Some("5ghz"), Some(0)).unwrap();
        assert!(s.width_assumed);
    }

    #[test]
    fn same_channel_fully_overlaps() {
        let own = span(6, Band::TwoGhz, 20);
        let h = overlap_hypothesis(&own, &span(6, Band::TwoGhz, 20), Some(-60));
        assert!((h.overlap - 1.0).abs() < 1e-9);
        assert_eq!(h.confidence, OverlapConfidence::High);
        assert_eq!(h.rssi_dbm, Some(-60));
    }

    /// The 2.4 GHz rule from the measurement: numbers 5 apart no longer overlap,
    /// and everything closer overlaps proportionally.
    #[test]
    fn two_ghz_overlaps_below_five_channels_apart() {
        let own = span(6, Band::TwoGhz, 20);
        let at = |c: i32| overlap_hypothesis(&own, &span(c, Band::TwoGhz, 20), None).overlap;
        assert!((at(7) - 0.8).abs() < 1e-9);
        assert!((at(4) - 0.6).abs() < 1e-9);
        assert!((at(2) - 0.2).abs() < 1e-9);
        assert_eq!(at(1), 0.0, "5 apart is the first non-overlapping pair");
        assert_eq!(at(11), 0.0);
    }

    #[test]
    fn different_bands_never_overlap() {
        let own = span(6, Band::TwoGhz, 20);
        assert_eq!(
            overlap_hypothesis(&own, &span(6, Band::FiveGhz, 20), Some(-50)).overlap,
            0.0
        );
        let own = span(36, Band::FiveGhz, 80);
        assert_eq!(
            overlap_hypothesis(&own, &span(36, Band::SixGhz, 80), Some(-50)).overlap,
            0.0
        );
    }

    /// A 20 MHz AP inside our 80 MHz channel covers all of the narrower channel:
    /// the fraction is of the NARROWER span, so it reads 1.0 from either side.
    #[test]
    fn five_ghz_narrow_inside_wide_is_total_for_the_narrow_one() {
        // Our 80 MHz channel centred on 36 spans 5140..5220; channel 40 (5200)
        // at 20 MHz spans 5190..5210, wholly inside.
        let own = span(36, Band::FiveGhz, 80);
        let h = overlap_hypothesis(&own, &span(40, Band::FiveGhz, 20), Some(-70));
        assert!((h.overlap - 1.0).abs() < 1e-9);
        // Symmetric: from the narrow radio's point of view the wide one covers
        // it just as completely.
        let h = overlap_hypothesis(&span(40, Band::FiveGhz, 20), &own, Some(-70));
        assert!((h.overlap - 1.0).abs() < 1e-9);
    }

    #[test]
    fn five_ghz_adjacent_channels_are_disjoint() {
        // 36 (5180) and 48 (5240) at 20 MHz: 5170..5190 vs 5230..5250.
        let h = overlap_hypothesis(
            &span(36, Band::FiveGhz, 20),
            &span(48, Band::FiveGhz, 20),
            Some(-70),
        );
        assert_eq!(h.overlap, 0.0);
    }

    #[test]
    fn five_ghz_partial_overlap_is_a_fraction() {
        // Our 20 MHz on 36 (5170..5190) against a 40 MHz on 38 (5190; 5170..5210):
        // shared 5170..5190 = 20 of our 20 MHz.
        let h = overlap_hypothesis(
            &span(36, Band::FiveGhz, 20),
            &span(38, Band::FiveGhz, 40),
            Some(-70),
        );
        assert!((h.overlap - 1.0).abs() < 1e-9);
        // Half-covering case: 40 MHz on 40 (5200; 5180..5220) over our 20 MHz on
        // 36 (5170..5190) shares 5180..5190 = 10 of 20.
        let h = overlap_hypothesis(
            &span(36, Band::FiveGhz, 20),
            &span(40, Band::FiveGhz, 40),
            Some(-70),
        );
        assert!((h.overlap - 0.5).abs() < 1e-9, "got {}", h.overlap);
    }

    #[test]
    fn six_ghz_uses_its_own_base_frequency() {
        // Same channel numbers, same band: still a full overlap.
        let h = overlap_hypothesis(
            &span(37, Band::SixGhz, 40),
            &span(37, Band::SixGhz, 40),
            None,
        );
        assert!((h.overlap - 1.0).abs() < 1e-9);
        // And 6 GHz channel 1 (5955) is nowhere near 5 GHz channel 1 (5005).
        assert_eq!(
            overlap_hypothesis(
                &span(1, Band::SixGhz, 20),
                &span(1, Band::FiveGhz, 20),
                None
            )
            .overlap,
            0.0
        );
    }

    #[test]
    fn confidence_degrades_with_what_was_not_reported() {
        let own = span(36, Band::FiveGhz, 80);
        assert_eq!(
            overlap_hypothesis(&own, &span(36, Band::FiveGhz, 80), None).confidence,
            OverlapConfidence::Medium
        );
        let assumed = ChannelSpan::new(Some(36), Some("5ghz"), None).unwrap();
        assert_eq!(
            overlap_hypothesis(&own, &assumed, Some(-60)).confidence,
            OverlapConfidence::Low
        );
        assert_eq!(
            overlap_hypothesis(&assumed, &span(36, Band::FiveGhz, 80), Some(-60)).confidence,
            OverlapConfidence::Low
        );
    }

    /// The ranking is overlap first, loudness second — never a single composite
    /// number that would read as measured.
    #[test]
    fn rank_orders_by_overlap_then_signal() {
        let own = span(36, Band::FiveGhz, 80);
        let strong_on_channel = overlap_hypothesis(&own, &span(36, Band::FiveGhz, 80), Some(-50));
        let weak_on_channel = overlap_hypothesis(&own, &span(36, Band::FiveGhz, 80), Some(-85));
        let strong_off_channel = overlap_hypothesis(&own, &span(149, Band::FiveGhz, 80), Some(-40));
        assert!(strong_on_channel.rank_key() > weak_on_channel.rank_key());
        assert!(weak_on_channel.rank_key() > strong_off_channel.rank_key());
    }
}
