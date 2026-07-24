//! Per-collector capability signals: a static OS declaration ([`CollectorMeta`]
//! over [`Os`]) and a runtime readiness verdict ([`Readiness`]). The daemon uses
//! both to decide, per collector, whether to run it at all.

/// The operating systems a collector can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
}

impl Os {
    /// The OS this binary is running on, resolved via `cfg!(target_os = ...)`.
    ///
    /// v1 ships macOS-only collectors; a build for any target that is neither
    /// macOS nor Linux still reports `MacOs` as a sane default.
    #[allow(clippy::if_same_then_else)] // v1 default: unknown targets fall back to MacOs
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::MacOs
        }
    }
}

/// Static metadata a collector declares about itself: its name and which OSes it
/// targets. Held as a `const` per collector crate.
#[derive(Debug, Clone, Copy)]
pub struct CollectorMeta {
    pub name: &'static str,
    pub supported_os: &'static [Os],
}

impl CollectorMeta {
    /// Whether this collector declares support for `os`.
    pub fn supports(&self, os: Os) -> bool {
        self.supported_os.contains(&os)
    }
}

/// Runtime "can this collector work here/now?" verdict from its preflight probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    Unavailable(String),
}

impl Readiness {
    /// Whether the collector passed preflight and may be spawned.
    pub fn is_ready(&self) -> bool {
        matches!(self, Readiness::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supports_matches_declared_os() {
        const M: CollectorMeta = CollectorMeta {
            name: "x",
            supported_os: &[Os::MacOs],
        };
        assert!(M.supports(Os::MacOs));
        assert!(!M.supports(Os::Linux));
    }
}
