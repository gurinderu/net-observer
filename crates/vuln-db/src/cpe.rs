//! The product-identity input to a match query.

/// A product to look up against the vulnerability index.
///
/// This is a deliberately small stand-in for a full CPE URI. A match needs a
/// product name; a vendor narrows it; a version enables range containment (and
/// thus a higher-confidence verdict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpe {
    /// Vendor, if known (e.g. `openbsd`). Compared case-insensitively.
    pub vendor: Option<String>,
    /// Product name (e.g. `openssh`). Compared case-insensitively.
    pub product: String,
    /// Version, if known (e.g. `7.4`). Enables version-range containment.
    pub version: Option<String>,
}

impl Cpe {
    /// Construct a product-only query.
    pub fn product(product: impl Into<String>) -> Self {
        Cpe {
            vendor: None,
            product: product.into(),
            version: None,
        }
    }

    /// Attach a vendor.
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Attach a version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}
