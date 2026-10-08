//! Facts about the machine and account the app is running as.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub computer: Option<String>,
    pub user: Option<String>,
    /// DNS name of the logon domain, when the account is a domain account.
    pub domain: Option<String>,
    pub os: &'static str,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub fn detect() -> Environment {
    if cfg!(windows) {
        Environment {
            computer: var("COMPUTERNAME"),
            user: match (var("USERDOMAIN"), var("USERNAME")) {
                (Some(d), Some(u)) => Some(format!("{d}\\{u}")),
                (None, u) => u,
                (Some(_), None) => None,
            },
            domain: var("USERDNSDOMAIN").map(|d| d.to_lowercase()),
            os: std::env::consts::OS,
        }
    } else {
        Environment {
            computer: var("HOSTNAME"),
            user: var("USER"),
            domain: None,
            os: std::env::consts::OS,
        }
    }
}
