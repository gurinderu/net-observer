//! Error type for the crate.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors that can arise while ingesting a snapshot.
///
/// Note the deliberate asymmetry: a *malformed individual record* is never an
/// error — it is skipped so that partial data still yields a usable index
/// ("absence is a signal", never a panic). These variants cover only failures
/// that make the whole ingest impossible: the snapshot directory is missing, or
/// an I/O error occurs while walking it.
#[derive(Debug, Error)]
pub enum VulnDbError {
    /// The snapshot directory does not exist or is not a directory.
    #[error("snapshot directory not found or not a directory: {0}")]
    SnapshotNotFound(PathBuf),

    /// An I/O error occurred while reading the snapshot tree.
    #[error("i/o error reading snapshot at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
