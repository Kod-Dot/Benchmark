//! Machine-readable exports: findings as CSV, SARIF, and the remediation
//! plan as CSV and XLSX.

use rust_xlsxwriter::{Color, Format, FormatBorder, Workbook};
use serde_json::{json, Value};

use crate::catalog::Severity;
use crate::results::{AssessmentView, Finding, ResultStatus};

pub fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

pub fn status_word(s: ResultStatus) -> &'static str {
    match s {
        ResultStatus::Failed => "Failed",
        ResultStatus::Passed => "Passed",
        ResultStatus::NotAssessed => "Not assessed",
        ResultStatus::Accepted => "Accepted risk",
    }
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// One CSV field, quoted when it needs to be. Fields that a spreadsheet
/// would run as a formula get a leading apostrophe.
fn field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv(header: &[&str], rows: &[Vec<String>]) -> String {
    // A BOM so Excel reads the file as UTF-8.
    let mut out = String::from("\u{feff}");
    out.push_str(
        &header
            .iter()
            .map(|h| field(h))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push_str("\r\n");
    for r in rows {
        out.push_str(&r.iter().map(|c| field(c)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

fn cvss_text(f: &Finding) -> String {
    f.cvss
        .as_ref()
        .map(|c| format!("{:.1}", c.score))
        .unwrap_or_default()
}

/// Every check result, one row each.
pub fn findings_csv(view: &AssessmentView) -> String {
    let rows: Vec<Vec<String>> = view
        .findings
        .iter()
        .map(|f| {
            vec![
                f.id.clone(),
                f.title.clone(),
                format!("{} {}", f.area, f.area_title),
                status_word(f.status).into(),
                severity_word(f.severity).into(),
                cvss_text(f),
                f.affected_count.map(|n| n.to_string()).unwrap_or_default(),
                f.affected_unit.clone().unwrap_or_default(),
                f.expected.clone().unwrap_or_default(),
                f.found.clone().unwrap_or_default(),
                f.note.clone().unwrap_or_default(),
                f.mitre
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                f.run.clone(),
            ]
        })
        .collect();
    csv(
        &[
            "Check ID",
            "Title",
            "Area",
            "Status",
            "Severity",
            "CVSS (estimated)",
            "Affected",
            "Affected unit",
            "Expected",
            "Found",
            "Note",
            "MITRE ATT&CK",
            "Assessment",
        ],
        &rows,
    )
}

/// SARIF 2.1.0: one rule per check that ran, one result per failed check.
pub fn sarif(view: &AssessmentView, tool_version: &str) -> Value {
    let level = |s: Severity| match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    };
    let rules: Vec<Value> = view
        .findings
        .iter()
        .map(|f| {
            let d = f.detail.as_ref();
            let mut rule = json!({
                "id": f.id,
                "name": f.id.replace('-', ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": d.map(|d| d.description.as_str()).unwrap_or(&f.title)},
                "defaultConfiguration": {"level": level(f.severity)},
                "properties": {
                    "tags": f.mitre.iter().map(|m| m.id.clone()).chain([f.area.clone()]).collect::<Vec<_>>(),
                    "severity": severity_word(f.severity),
                },
            });
            if let Some(d) = d {
                if !d.remediation.is_empty() {
                    rule["help"] = json!({"text": d.remediation.join("\n")});
                }
                if let Some(r) = d.references.first() {
                    rule["helpUri"] = json!(r.url);
                }
            }
            if let Some(c) = &f.cvss {
                rule["properties"]["security-severity"] = json!(format!("{:.1}", c.score));
            }
            rule
        })
        .collect();
    let results: Vec<Value> = view
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.status == ResultStatus::Failed)
        .map(|(i, f)| {
            let text = match &f.found {
                Some(found) => format!("{}. Found: {found}", f.title),
                None => f.title.clone(),
            };
            let locations: Vec<Value> = f
                .affected
                .iter()
                .take(50)
                .map(|a| {
                    json!({"logicalLocations": [{
                        "name": a.name,
                        "kind": a.kind,
                        "fullyQualifiedName": a.location.clone().unwrap_or_else(|| a.name.clone()),
                    }]})
                })
                .collect();
            let mut r = json!({
                "ruleId": f.id,
                "ruleIndex": i,
                "level": level(f.severity),
                "message": {"text": text},
            });
            if !locations.is_empty() {
                r["locations"] = json!(locations);
            }
            r
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Benchmark",
                "version": tool_version,
                "informationUri": "https://github.com/Kod-Dot/Benchmark",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

// ---------- Remediation plan ----------

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlanRow {
    pub order: usize,
    pub id: String,
    pub title: String,
    pub area: String,
    pub severity: Severity,
    pub cvss: String,
    pub affected: String,
    pub effort: &'static str,
    pub phase: u32,
    pub quick_win: bool,
    pub owner: &'static str,
    pub status: &'static str,
    pub first_step: String,
    pub verify: String,
}

/// Effort from how many objects need changing. An estimate: the plan says so.
fn effort(f: &Finding) -> &'static str {
    match f.affected_count.unwrap_or(1) {
        0..=3 => "S",
        4..=50 => "M",
        _ => "L",
    }
}

fn phase(s: Severity, effort: &str) -> u32 {
    match (s, effort) {
        (Severity::Critical, _) => 30,
        (Severity::High, "L") => 90,
        (Severity::High, _) => 30,
        (Severity::Medium, "L") => 180,
        (Severity::Medium, _) => 90,
        _ => 180,
    }
}

/// The team that usually owns the fix, by area.
pub fn owner(area: &str) -> &'static str {
    let prefix = area.rsplit_once('-').map(|(p, _)| p).unwrap_or(area);
    match area {
        "AD-DC" | "AD-LEG" | "AD-AUD" | "AD-BKP" | "AD-REP" | "AD-DNS" => {
            "Domain controller administrators"
        }
        "AD-PRIV" | "AD-ACL" | "AD-FND" | "AD-TRU" | "AD-OU" | "AD-SCH" => {
            "Tier 0 / AD architecture"
        }
        "AD-KRB" | "AD-PWD" | "AD-ACC" | "AD-SVC" | "AD-LAPS" | "AD-CMP" | "AD-APP" => {
            "Identity and account management"
        }
        "AD-GPO" => "Group Policy administrators",
        "AD-PKI" => "PKI administrators",
        _ => match prefix {
            "EID" | "ENTRA" => "Entra ID administrators",
            "HYB" => "Hybrid identity administrators",
            _ => "Security team",
        },
    }
}

/// Failed findings (and accepted risks unless `omit_accepted`), in the
/// order to fix them: by phase, then severity, quick wins first, then CVSS.
pub fn remediation(view: &AssessmentView, omit_accepted: bool) -> Vec<PlanRow> {
    let mut rows: Vec<PlanRow> = view
        .findings
        .iter()
        .filter(|f| {
            f.status == ResultStatus::Failed
                || (!omit_accepted && f.status == ResultStatus::Accepted)
        })
        .map(|f| {
            let e = effort(f);
            let p = phase(f.severity, e);
            let d = f.detail.as_ref();
            PlanRow {
                order: 0,
                id: f.id.clone(),
                title: f.title.clone(),
                area: f.area_title.clone(),
                severity: f.severity,
                cvss: cvss_text(f),
                affected: match (f.affected_count, &f.affected_unit) {
                    (Some(n), Some(u)) => format!("{n} {u}"),
                    (Some(n), None) => n.to_string(),
                    _ => String::new(),
                },
                effort: e,
                phase: p,
                quick_win: e == "S" && rank(f.severity) >= rank(Severity::Medium),
                owner: owner(&f.area),
                status: status_word(f.status),
                first_step: d
                    .and_then(|d| d.remediation.first().cloned())
                    .unwrap_or_default(),
                verify: d.and_then(|d| d.verify.clone()).unwrap_or_default(),
            }
        })
        .collect();
    let cvss = |r: &PlanRow| r.cvss.parse::<f64>().unwrap_or(0.0);
    rows.sort_by(|a, b| {
        a.phase
            .cmp(&b.phase)
            .then(rank(b.severity).cmp(&rank(a.severity)))
            .then(b.quick_win.cmp(&a.quick_win))
            .then(cvss(b).total_cmp(&cvss(a)))
            .then(a.id.cmp(&b.id))
    });
    for (i, r) in rows.iter_mut().enumerate() {
        r.order = i + 1;
    }
    rows
}

const PLAN_HEADER: [&str; 14] = [
    "Order",
    "Fix within (days)",
    "Check ID",
    "Finding",
    "Area",
    "Severity",
    "CVSS (estimated)",
    "Affected",
    "Effort (estimated)",
    "Quick win",
    "Suggested owner",
    "Status",
    "First step",
    "How to verify",
];

fn plan_cells(r: &PlanRow) -> Vec<String> {
    vec![
        r.order.to_string(),
        r.phase.to_string(),
        r.id.clone(),
        r.title.clone(),
        r.area.clone(),
        severity_word(r.severity).into(),
        r.cvss.clone(),
        r.affected.clone(),
        r.effort.into(),
        if r.quick_win {
            "Yes".into()
        } else {
            String::new()
        },
        r.owner.into(),
        r.status.into(),
        r.first_step.clone(),
        r.verify.clone(),
    ]
}

pub fn remediation_csv(rows: &[PlanRow]) -> String {
    csv(
        &PLAN_HEADER,
        &rows.iter().map(plan_cells).collect::<Vec<_>>(),
    )
}

fn sev_colour(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::RGB(0xB3261E),
        Severity::High => Color::RGB(0xB5470B),
        Severity::Medium => Color::RGB(0xE9B949),
        _ => Color::RGB(0x3B6E3B),
    }
}

/// The plan as a workbook: the plan itself, then every affected object of
/// the planned findings.
pub fn remediation_xlsx(
    rows: &[PlanRow],
    view: &AssessmentView,
    title: &str,
) -> Result<Vec<u8>, String> {
    let e = |e: rust_xlsxwriter::XlsxError| e.to_string();
    let mut book = Workbook::new();
    let header = Format::new()
        .set_bold()
        .set_font_color(Color::RGB(0x3D3929))
        .set_background_color(Color::RGB(0xF0EEE6))
        .set_border_bottom(FormatBorder::Thin)
        .set_text_wrap();
    let wrap = Format::new()
        .set_text_wrap()
        .set_align(rust_xlsxwriter::FormatAlign::Top);
    let top = Format::new().set_align(rust_xlsxwriter::FormatAlign::Top);
    let title_fmt = Format::new().set_bold().set_font_size(14);

    let sheet = book.add_worksheet();
    sheet.set_name("Remediation plan").map_err(e)?;
    sheet
        .write_string_with_format(0, 0, title, &title_fmt)
        .map_err(e)?;
    sheet
        .write_string(1, 0, "Effort, order and owner are estimates from severity and the number of affected objects. Adjust them to your environment.")
        .map_err(e)?;
    let first = 3u32;
    for (c, h) in PLAN_HEADER.iter().enumerate() {
        sheet
            .write_string_with_format(first, c as u16, *h, &header)
            .map_err(e)?;
    }
    for (i, r) in rows.iter().enumerate() {
        let row = first + 1 + i as u32;
        sheet
            .write_number_with_format(row, 0, r.order as f64, &top)
            .map_err(e)?;
        sheet
            .write_number_with_format(row, 1, f64::from(r.phase), &top)
            .map_err(e)?;
        let sev = Format::new()
            .set_bold()
            .set_font_color(Color::White)
            .set_background_color(sev_colour(r.severity))
            .set_align(rust_xlsxwriter::FormatAlign::Top);
        for (c, v) in plan_cells(r).into_iter().enumerate().skip(2) {
            let fmt = if c == 5 {
                &sev
            } else if matches!(c, 3 | 12 | 13) {
                &wrap
            } else {
                &top
            };
            if c == 6 && !v.is_empty() {
                sheet
                    .write_number_with_format(row, c as u16, v.parse::<f64>().unwrap_or(0.0), fmt)
                    .map_err(e)?;
            } else {
                sheet
                    .write_string_with_format(row, c as u16, &v, fmt)
                    .map_err(e)?;
            }
        }
    }
    for (c, w) in [
        7.0, 9.0, 13.0, 48.0, 26.0, 10.0, 9.0, 18.0, 10.0, 8.0, 28.0, 12.0, 60.0, 50.0,
    ]
    .into_iter()
    .enumerate()
    {
        sheet.set_column_width(c as u16, w).map_err(e)?;
    }
    sheet.set_freeze_panes(first + 1, 0).map_err(e)?;
    if !rows.is_empty() {
        sheet
            .autofilter(
                first,
                0,
                first + rows.len() as u32,
                PLAN_HEADER.len() as u16 - 1,
            )
            .map_err(e)?;
    }

    let objects = book.add_worksheet();
    objects.set_name("Affected objects").map_err(e)?;
    for (c, h) in ["Check ID", "Finding", "Object", "Kind", "Location", "Why"]
        .iter()
        .enumerate()
    {
        objects
            .write_string_with_format(0, c as u16, *h, &header)
            .map_err(e)?;
    }
    let mut row = 1u32;
    for r in rows {
        let Some(f) = view.findings.iter().find(|f| f.id == r.id) else {
            continue;
        };
        for a in &f.affected {
            for (c, v) in [
                f.id.as_str(),
                f.title.as_str(),
                a.name.as_str(),
                a.kind.as_str(),
                a.location.as_deref().unwrap_or(""),
                a.reason.as_deref().unwrap_or(""),
            ]
            .into_iter()
            .enumerate()
            {
                objects.write_string(row, c as u16, v).map_err(e)?;
            }
            row += 1;
        }
    }
    for (c, w) in [13.0, 40.0, 32.0, 12.0, 60.0, 60.0].into_iter().enumerate() {
        objects.set_column_width(c as u16, w).map_err(e)?;
    }
    objects.set_freeze_panes(1, 0).map_err(e)?;
    if row > 1 {
        objects.autofilter(0, 0, row - 1, 5).map_err(e)?;
    }
    book.save_to_buffer().map_err(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_formulas_neutralised() {
        assert_eq!(field("plain"), "plain");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("=cmd|' /c calc'!A1"), "'=cmd|' /c calc'!A1");
    }

    #[test]
    fn phases_follow_severity_and_effort() {
        assert_eq!(phase(Severity::Critical, "L"), 30);
        assert_eq!(phase(Severity::High, "S"), 30);
        assert_eq!(phase(Severity::High, "L"), 90);
        assert_eq!(phase(Severity::Medium, "M"), 90);
        assert_eq!(phase(Severity::Low, "S"), 180);
    }
}
