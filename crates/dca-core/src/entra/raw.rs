//! Reads what `collectors/Invoke-DCAEntra.ps1` wrote for one tenant:
//! `collection.json`, one `<area>.jsonl` of Graph response pages per area,
//! and the `events.jsonl` log the collector host keeps.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ad::raw::{io_err, read_lines, AreaState, CollectEvent};
use crate::{Error, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantInfo {
    pub tenant: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub computer: String,
    pub started_at: String,
    #[serde(default)]
    pub sources: Vec<String>,
    /// Delegated permissions the sign-in was granted.
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RawTenant {
    pub info: TenantInfo,
    pub finished_at: Option<String>,
    pub areas: BTreeMap<String, AreaState>,
    /// Items per area, flattened from the response pages. Items read per
    /// parent carry the parent's id as `@dca.parent`.
    pub data: BTreeMap<String, Vec<Value>>,
    /// Areas where Graph had more records than the collector reads.
    pub truncated: std::collections::BTreeSet<String>,
}

/// The items of one response page: its `value` array, or the page itself
/// for endpoints that return a single object.
fn items(mut page: Value, out: &mut Vec<Value>) {
    let parent = page.get("@dca.parent").cloned();
    // A $count request's total, kept on each item of its page.
    let count = page.get("@odata.count").cloned();
    match page.get_mut("value").map(Value::take) {
        Some(Value::Array(list)) => {
            for mut item in list {
                if let Some(map) = item.as_object_mut() {
                    if let Some(p) = &parent {
                        map.insert("@dca.parent".into(), p.clone());
                    }
                    if let Some(c) = &count {
                        map.insert("@odata.count".into(), c.clone());
                    }
                }
                out.push(item);
            }
        }
        _ => {
            if let Some(map) = page.as_object_mut() {
                map.remove("@odata.context");
            }
            out.push(page);
        }
    }
}

impl RawTenant {
    pub fn area(&self, name: &str) -> &AreaState {
        static MISSING: AreaState = AreaState::Missing;
        self.areas.get(name).unwrap_or(&MISSING)
    }

    pub fn list(&self, area: &str) -> &[Value] {
        self.data.get(area).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The single object an area returned (a policy, the organization).
    pub fn first(&self, area: &str) -> Option<&Value> {
        self.list(area).first()
    }

    pub fn read(&self, area: &str) -> bool {
        matches!(self.area(area), AreaState::Read(_))
    }

    pub fn load(dir: &Path) -> Result<RawTenant> {
        let info_path = dir.join("collection.json");
        let text = fs::read_to_string(&info_path).map_err(|e| io_err(&info_path, e))?;
        let info: TenantInfo =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| {
                Error::Parse {
                    path: info_path.display().to_string(),
                    message: e.to_string(),
                }
            })?;
        let mut raw = RawTenant {
            info,
            ..RawTenant::default()
        };
        for event in read_lines::<CollectEvent>(&dir.join("events.jsonl"))? {
            match event {
                CollectEvent::Done { area, count } => {
                    raw.areas.insert(area, AreaState::Read(count));
                }
                CollectEvent::Error { area, message } => {
                    raw.areas.insert(area, AreaState::Failed(message));
                }
                CollectEvent::Finished { finished_at } => raw.finished_at = Some(finished_at),
                _ => {}
            }
        }
        let mut files: Vec<_> = fs::read_dir(dir)
            .map_err(|e| io_err(dir, e))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "jsonl")
                    && p.file_stem().is_some_and(|s| s != "events")
            })
            .collect();
        files.sort();
        for path in files {
            let area = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let mut list = Vec::new();
            for page in read_lines::<Value>(&path)? {
                if page.get("@dca.truncated").is_some() {
                    raw.truncated.insert(area.clone());
                    continue;
                }
                items(page, &mut list);
            }
            raw.data.insert(area, list);
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_flatten_with_parent() {
        let mut out = Vec::new();
        items(
            serde_json::json!({"@dca.parent": "d1", "@odata.context": "x", "@odata.count": 7, "value": [{"id": "a"}, {"id": "b"}]}),
            &mut out,
        );
        items(
            serde_json::json!({"@odata.context": "x", "id": "policy"}),
            &mut out,
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["@dca.parent"], "d1");
        assert_eq!(out[1]["@odata.count"], 7);
        assert_eq!(out[2]["id"], "policy");
        assert!(out[2].get("@odata.context").is_none());
    }
}
