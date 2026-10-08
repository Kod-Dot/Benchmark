//! Core of Benchmark: the check catalog, the assessments store, results and
//! scoring, comparing runs, environment detection and access probing. Everything here is read-only and has no UI
//! or Tauri dependency, so it is unit-tested on any platform.

pub mod access;
pub mod account;
pub mod ad;
pub mod analysis;
pub mod bundle;
pub mod catalog;
pub mod compare;
pub mod cvss;
pub mod entra;
pub mod environment;
pub mod exceptions;
pub mod hybrid;
pub mod report;
pub mod results;
pub mod store;
pub mod time;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid file {path}: {message}")]
    Parse { path: String, message: String },
    #[error("catalog is inconsistent: {0}")]
    Catalog(String),
    #[error("{0}")]
    Assessment(String),
}

pub type Result<T> = std::result::Result<T, Error>;
