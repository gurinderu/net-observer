//! `collector-singbox-log` — the `singbox-log` collector: a passive reader of
//! sing-box's own log, whose ERROR/WARN lines are the one place its dial
//! failures and its "missing default interface" are written (realm
//! net-observer, nodes #140, #141).
//!
//! Each tick the collector reads the bytes appended to the log since the last
//! tick ([`tail::LogTail`]), keeps the ERROR/WARN lines (a byte scan for the
//! level token before any parsing — the log is DEBUG-level and large), parses
//! each ([`parse::parse_line`]), classes it ([`classify::classify`]) and folds
//! the classes into one [`types::SingboxLogSample`] per `(class, node)`. It
//! reads a world-readable local file and sends nothing, so it runs under both
//! probing tiers.

pub mod classify;
pub mod collector;
pub mod parse;
pub mod tail;

pub use collector::{META, SingboxLogCollector, TailSource, fold_lines};
pub use tail::LogTail;
