//! CVSS 3.1 base scores. Configuration weaknesses have no vendor CVSS, so
//! the catalog carries our own estimated vector and the UI labels the score
//! as an estimate. The formula is the one in the CVSS 3.1 specification §7.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Cvss {
    pub vector: String,
    pub score: f64,
    /// Plain-language reading of each base metric, in specification order.
    pub metrics: Vec<(String, String)>,
}

pub fn parse(vector: &str) -> Result<Cvss, String> {
    let score = base_score(vector)?;
    let mut metrics = Vec::new();
    for (key, value) in fields(vector)? {
        let (name, reading) = match (key, value) {
            ("AV", v) => (
                "Attack vector",
                match v {
                    "N" => "Network",
                    "A" => "Adjacent",
                    "L" => "Local",
                    _ => "Physical",
                },
            ),
            ("AC", v) => ("Attack complexity", if v == "L" { "Low" } else { "High" }),
            ("PR", v) => (
                "Privileges required",
                match v {
                    "N" => "None",
                    "L" => "Low",
                    _ => "High",
                },
            ),
            ("UI", v) => (
                "User interaction",
                if v == "N" { "None" } else { "Required" },
            ),
            ("S", v) => ("Scope", if v == "U" { "Unchanged" } else { "Changed" }),
            ("C", v) => ("Confidentiality", level(v)),
            ("I", v) => ("Integrity", level(v)),
            ("A", v) => ("Availability", level(v)),
            _ => continue,
        };
        metrics.push((name.to_string(), reading.to_string()));
    }
    Ok(Cvss {
        vector: vector.to_string(),
        score,
        metrics,
    })
}

fn level(v: &str) -> &'static str {
    match v {
        "H" => "High",
        "L" => "Low",
        _ => "None",
    }
}

const ORDER: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

fn fields(vector: &str) -> Result<Vec<(&str, &str)>, String> {
    let body = vector.strip_prefix("CVSS:3.1/").unwrap_or(vector);
    let pairs: Vec<(&str, &str)> = body
        .split('/')
        .map(|p| {
            p.split_once(':')
                .ok_or_else(|| format!("'{p}' is not metric:value"))
        })
        .collect::<Result<_, _>>()?;
    let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
    if keys != ORDER {
        return Err(format!(
            "expected the metrics {} in that order",
            ORDER.join("/")
        ));
    }
    Ok(pairs)
}

pub fn base_score(vector: &str) -> Result<f64, String> {
    let f = fields(vector)?;
    let get = |k: &str| {
        f.iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| *v)
            .unwrap_or("")
    };
    let bad = |k: &str| format!("invalid value {}:{}", k, get(k));
    let changed = match get("S") {
        "U" => false,
        "C" => true,
        _ => return Err(bad("S")),
    };
    let av = match get("AV") {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return Err(bad("AV")),
    };
    let ac = match get("AC") {
        "L" => 0.77,
        "H" => 0.44,
        _ => return Err(bad("AC")),
    };
    let pr = match (get("PR"), changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return Err(bad("PR")),
    };
    let ui = match get("UI") {
        "N" => 0.85,
        "R" => 0.62,
        _ => return Err(bad("UI")),
    };
    let cia = |k: &str| match get(k) {
        "H" => Ok(0.56),
        "L" => Ok(0.22),
        "N" => Ok(0.0),
        _ => Err(bad(k)),
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Ok(0.0);
    }
    let raw = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Ok(round_up(raw))
}

/// The specification's Roundup: smallest one-decimal number >= x, computed
/// on integers to avoid floating point surprises.
fn round_up(x: f64) -> f64 {
    let int = (x * 100_000.0).round() as i64;
    if int % 10_000 == 0 {
        int as f64 / 100_000.0
    } else {
        ((int / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_scores() {
        // Values checked against the FIRST CVSS 3.1 calculator.
        assert_eq!(
            base_score("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").unwrap(),
            9.9
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap(),
            9.8
        );
        assert_eq!(
            base_score("AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N").unwrap(),
            6.8
        );
        assert_eq!(
            base_score("AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N").unwrap(),
            2.3
        );
        assert_eq!(
            base_score("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N").unwrap(),
            0.0
        );
    }

    #[test]
    fn rejects_bad_vectors() {
        assert!(base_score("AV:N/AC:L").is_err());
        assert!(base_score("AV:X/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn describes_metrics() {
        let c = parse("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert_eq!(c.metrics[0], ("Attack vector".into(), "Network".into()));
        assert_eq!(c.metrics.len(), 8);
    }
}
