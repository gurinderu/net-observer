//! Error type for the crate.
//!
//! The decoder is a forensics tool: it must never panic on malformed input.
//! Structural failures that make a *whole* PDU undecodable surface as one of
//! these variants; a single unknown or unreadable optional field is skipped
//! rather than raised (see the crate docs), so this enum stays small.

use thiserror::Error;

/// Errors that can arise while decoding an LLDP or CDP PDU.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LldpError {
    /// A read ran past the end of the buffer. `context` names the field whose
    /// declared length or fixed size did not fit in the remaining bytes.
    #[error("truncated input while reading {context}: need {need} byte(s), have {have}")]
    Truncated {
        /// Human-readable name of the field being read when the buffer ran out.
        context: &'static str,
        /// Number of bytes the read required.
        need: usize,
        /// Number of bytes actually remaining.
        have: usize,
    },

    /// The PDU was structurally well-formed enough to walk, but a mandatory
    /// field was absent (e.g. an LLDPDU with no Chassis ID before End-of-LLDPDU).
    #[error("missing mandatory field: {0}")]
    MissingMandatory(&'static str),

    /// A field carried a length that cannot be valid for its kind (e.g. a CDP
    /// TLV whose declared length is smaller than its own 4-byte header).
    #[error("malformed {context}: {detail}")]
    Malformed {
        /// Human-readable name of the offending structure.
        context: &'static str,
        /// Why it is malformed.
        detail: &'static str,
    },

    /// The input was empty.
    #[error("empty input")]
    Empty,
}
