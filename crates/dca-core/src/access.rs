//! Access checks: which data sources the selected areas need, and parsing
//! of the probe results that `collectors/Test-DCAAccess.ps1` writes as JSON
//! lines on stdout.

use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;

/// Source ids needed by `area_codes`, in the catalog's source order.
pub fn required_sources(catalog: &Catalog, area_codes: &[String]) -> Vec<String> {
    catalog
        .sources
        .iter()
        .filter(|s| {
            catalog
                .areas
                .iter()
                .filter(|a| area_codes.contains(&a.code))
                .any(|a| a.sources.contains(&s.id))
        })
        .map(|s| s.id.clone())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeState {
    /// The source was read successfully.
    Ok,
    /// Some targets could be read, others not (for example 2 of 5 DCs).
    Partial,
    /// The source could not be read.
    Failed,
    /// Not testable up front (for example endpoints, which are tested per
    /// machine during collection).
    Untested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub source: String,
    pub state: ProbeState,
    pub detail: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Line {
    Probe(ProbeResult),
}

/// Parses one stdout line from the probe script. Lines that are not probe
/// results (blank lines, PowerShell noise) return `None`.
pub fn parse_probe_line(line: &str) -> Option<ProbeResult> {
    match serde_json::from_str::<Line>(line.trim()) {
        Ok(Line::Probe(p)) => Some(p),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn required_sources_follow_catalog_order() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks");
        let catalog = Catalog::load(&dir).unwrap();
        let got = required_sources(&catalog, &["AD-LEG".into(), "AD-FND".into()]);
        assert_eq!(got, ["ldap", "dc-remote", "dc-events"]);
    }

    #[test]
    fn parses_probe_lines_and_ignores_noise() {
        let p = parse_probe_line(
            r#"{"type":"probe","source":"ldap","state":"ok","detail":"Read RootDSE from dc01.corp.example"}"#,
        )
        .unwrap();
        assert_eq!(p.source, "ldap");
        assert_eq!(p.state, ProbeState::Ok);
        assert!(parse_probe_line("WARNING: something").is_none());
        assert!(parse_probe_line("").is_none());
    }
}
