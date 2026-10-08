//! What the collector read from member servers and workstations over
//! PowerShell remoting (`endpoints.jsonl`). A machine that could not be
//! reached keeps its name and the error, so checks can say which machines
//! they could not assess.

use serde::Deserialize;
use serde_json::Value;

use crate::entra::model::J;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Endpoint {
    pub name: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub read_at: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
}

/// Windows ProductType: 1 workstation, 2 domain controller, 3 server.
pub const WORKSTATION: i64 = 1;

impl Endpoint {
    /// A part of the reply, when it was read.
    pub fn part(&self, name: &str) -> Option<&Value> {
        self.data.as_ref()?.get(name).filter(|v| !v.is_null())
    }

    /// Why a part is missing, in words.
    pub fn why(&self, part: &str) -> String {
        match self
            .data
            .as_ref()
            .and_then(|d| d.at(&["errors", part]))
            .and_then(Value::as_str)
        {
            Some(e) => format!("{part} could not be read: {e}"),
            None => format!("{part} was not returned"),
        }
    }

    pub fn reg(&self, key: &str) -> Option<&Value> {
        self.part("registry")?.get(key).filter(|v| !v.is_null())
    }

    /// A registry value as an integer; `None` when it is not set.
    pub fn reg_int(&self, key: &str) -> Option<i64> {
        match self.reg(key)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    pub fn reg_str(&self, key: &str) -> Option<String> {
        match self.reg(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn services(&self) -> &[Value] {
        self.part("services")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn service(&self, name: &str) -> Option<&Value> {
        self.services()
            .iter()
            .find(|s| s.s("name").is_some_and(|n| n.eq_ignore_ascii_case(name)))
    }

    /// Running, or set to start automatically.
    pub fn service_active(&self, name: &str) -> Option<bool> {
        self.part("services")?;
        Some(
            self.service(name)
                .is_some_and(|s| s.s("state") == Some("Running") || s.s("start") == Some("Auto")),
        )
    }

    pub fn product_type(&self) -> Option<i64> {
        self.part("os")?.n("product_type")
    }

    pub fn build(&self) -> Option<i64> {
        self.part("os")?.n("build")
    }

    /// The short computer name, lower case.
    pub fn short(&self) -> String {
        self.name
            .split('.')
            .next()
            .unwrap_or(&self.name)
            .to_ascii_lowercase()
    }
}
