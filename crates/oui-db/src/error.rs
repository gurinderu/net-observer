//! Error type for the crate.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors that can arise while ingesting a snapshot.
///
/// Note the deliberate asymmetry: a *malformed individual line* is never an
/// error — it is skipped so that a partial registry still yields a usable index
/// ("absence is a signal", never a panic). This variant covers only the failure
/// that makes the whole ingest impossible: the snapshot file is missing, or an
/// I/O error occurs while reading it.
#[derive(Debug, Error)]
pub enum OuiDbError {
    /// An I/O error occurred while reading the snapshot file.
    #[error("i/o error reading oui snapshot at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
