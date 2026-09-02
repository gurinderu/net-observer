//! A small, conservative version comparator for service versions.
//!
//! Service banners do not carry semver. They carry dotted-numeric-with-suffix
//! forms such as `7.4`, `1.2.3p1`, `8.2.0`. This module parses those into an
//! ordered token sequence and compares them.
//!
//! The guiding rule is **conservatism**: an input we cannot parse is never
//! claimed to be inside a range. We would rather miss a match than assert a
//! wrong one — silent wrong data is worse than no data.
//!
//! ## Parsing
//! A version string is tokenised into a sequence of tokens, splitting on the
//! separators `.`, `-`, `_`, `+` and at every digit/non-digit boundary:
//! - a run of digits becomes [`Token::Num`];
//! - a run of other alphanumerics becomes [`Token::Alpha`].
//!
//! So `1.2.3p1` becomes `[Num(1), Num(2), Num(3), Alpha("p"), Num(1)]` and
//! `7.2p2` becomes `[Num(7), Num(2), Alpha("p"), Num(2)]`.
//!
//! ## Ordering
//! Tokens compare positionally. At a given position a [`Token::Num`] ranks
//! below a [`Token::Alpha`], and a missing token (the shorter sequence) ranks
//! below any present token. Thus `7.2 < 7.2p2 < 7.4`.
//!
//! A string with no digit at all (`unknown`, `*`, `n/a`) or that is empty is
//! treated as unparseable and yields `None`.

use std::cmp::Ordering;

/// A single component of a parsed version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Num(u64),
    Alpha(String),
}

impl Token {
    /// Rank of the token kind: numeric components sort below alphabetic ones.
    fn kind_rank(&self) -> u8 {
        match self {
            Token::Num(_) => 0,
            Token::Alpha(_) => 1,
        }
    }
}

impl Ord for Token {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Token::Num(a), Token::Num(b)) => a.cmp(b),
            (Token::Alpha(a), Token::Alpha(b)) => a.cmp(b),
            _ => self.kind_rank().cmp(&other.kind_rank()),
        }
    }
}

impl PartialOrd for Token {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed, comparable version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    tokens: Vec<Token>,
}

impl Version {
    /// Parse a version string. Returns `None` when the input carries no digit
    /// (e.g. `unknown`, `*`, `n/a`) or is empty — such inputs are unparseable
    /// and must never be claimed to sit inside a range.
    pub fn parse(raw: &str) -> Option<Version> {
        let mut tokens = Vec::new();
        let mut chars = raw.chars().peekable();
        let mut saw_digit = false;

        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                let mut n: u64 = 0;
                while let Some(&d) = chars.peek() {
                    if let Some(digit) = d.to_digit(10) {
                        saw_digit = true;
                        // Saturate on the (pathological) overflow of a numeric
                        // component rather than panicking or wrapping.
                        n = n.saturating_mul(10).saturating_add(u64::from(digit));
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Num(n));
            } else if c.is_ascii_alphabetic() {
                let mut s = String::new();
                while let Some(&a) = chars.peek() {
                    if a.is_ascii_alphabetic() {
                        s.push(a.to_ascii_lowercase());
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Alpha(s));
            } else {
                // Separator or anything else: consume and split here.
                chars.next();
            }
        }

        if !saw_digit || tokens.is_empty() {
            return None;
        }
        Some(Version { tokens })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut a = self.tokens.iter();
        let mut b = other.tokens.iter();
        loop {
            match (a.next(), b.next()) {
                (Some(x), Some(y)) => match x.cmp(y) {
                    Ordering::Equal => continue,
                    non_eq => return non_eq,
                },
                // A missing token ranks below any present token.
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (None, None) => return Ordering::Equal,
            }
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A half-open/closed version range, as expressed by CVE applicability data.
///
/// Any bound may be absent. An absent lower bound means "from the beginning";
/// an absent upper bound means "unbounded above". Bounds carry their own
/// inclusivity.
#[derive(Debug, Clone, Default)]
pub struct VersionRange {
    pub start_including: Option<String>,
    pub start_excluding: Option<String>,
    pub end_including: Option<String>,
    pub end_excluding: Option<String>,
    /// An exact single version (`version` with no upper bound). When set, the
    /// range matches only that version.
    pub exact: Option<String>,
}

impl VersionRange {
    /// Does this range have any usable bound at all? A range with no parseable
    /// bound cannot constrain a version and matches the whole product.
    pub fn is_unbounded(&self) -> bool {
        self.exact.is_none()
            && self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
    }

    /// Test whether `version` falls inside this range.
    ///
    /// Returns `None` when the answer cannot be established conservatively:
    /// the queried version is unparseable, or a bound that would decide the
    /// question is itself unparseable. `None` must be read as "no confident
    /// match", never as a match.
    pub fn contains(&self, version: &str) -> Option<bool> {
        let v = Version::parse(version)?;

        if let Some(exact) = &self.exact {
            let e = Version::parse(exact)?;
            return Some(v == e);
        }

        // Lower bound.
        if let Some(s) = &self.start_including {
            let sv = Version::parse(s)?;
            if v < sv {
                return Some(false);
            }
        }
        if let Some(s) = &self.start_excluding {
            let sv = Version::parse(s)?;
            if v <= sv {
                return Some(false);
            }
        }
        // Upper bound.
        if let Some(e) = &self.end_including {
            let ev = Version::parse(e)?;
            if v > ev {
                return Some(false);
            }
        }
        if let Some(e) = &self.end_excluding {
            let ev = Version::parse(e)?;
            if v >= ev {
                return Some(false);
            }
        }
        Some(true)
    }
}
