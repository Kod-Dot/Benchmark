//! Turns a page of the built UI (index.html or report.html) into one
//! self-contained HTML file: scripts, styles and fonts inlined, and the data
//! the page shows embedded as `window.__DCA__`. The file opens in any
//! browser without Benchmark and without a network.

use base64::Engine as _;

/// Where the built UI files come from: the app's embedded assets, or a
/// `dist` folder.
pub trait UiAssets {
    /// `path` as the HTML references it, for example `/assets/index-1a2b.js`.
    fn get(&self, path: &str) -> Option<Vec<u8>>;
}

pub struct DirAssets(pub std::path::PathBuf);

impl UiAssets for DirAssets {
    fn get(&self, path: &str) -> Option<Vec<u8>> {
        let rel = path.trim_start_matches(['/', '.']).trim_start_matches('/');
        if rel.split('/').any(|p| p == "..") {
            return None;
        }
        std::fs::read(self.0.join(rel)).ok()
    }
}

/// The value of `attr="..."` in one tag.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')? + start;
    Some(&tag[start..end])
}

/// Replaces every `url(...)` that points at a bundled font with a data URI.
/// Only Latin subsets are embedded, which keeps each file small; other
/// subsets fall back to system fonts.
fn inline_fonts(css: &str, assets: &dyn UiAssets) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(i) = rest.find("url(") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 4..];
        let Some(end) = after.find(')') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let target = after[..end].trim().trim_matches(['"', '\'']);
        let replacement = if target.ends_with(".woff2") {
            let name = target.rsplit('/').next().unwrap_or(target);
            let latin = name.contains("-latin-wght") || name.contains("-latin-ext-wght");
            match assets.get(target).filter(|_| latin) {
                Some(bytes) => format!(
                    "url(data:font/woff2;base64,{})",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                ),
                None => "url(data:font/woff2;base64,)".to_string(),
            }
        } else {
            format!("url({})", &after[..end])
        };
        out.push_str(&replacement);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The exported file runs only its own inlined code and loads nothing from
/// anywhere, so a report cannot call out over the network when opened.
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:";

/// JSON that is safe inside a `<script>` element.
fn script_json(data: &serde_json::Value) -> String {
    serde_json::to_string(data)
        .unwrap_or_else(|_| "null".into())
        .replace("</", "<\\/")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Builds the self-contained page from `entry` (for example `report.html`).
pub fn page(
    assets: &dyn UiAssets,
    entry: &str,
    title: &str,
    data: &serde_json::Value,
) -> Result<String, String> {
    let html = assets
        .get(entry)
        .ok_or_else(|| format!("The built interface has no {entry}."))?;
    let html = String::from_utf8(html).map_err(|e| e.to_string())?;

    let mut out = String::with_capacity(html.len() + (1 << 20));
    let mut rest = html.as_str();
    let mut scripts = Vec::new();
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find('>') else {
            out.push_str(tail);
            rest = "";
            break;
        };
        let tag = &tail[..=end];
        if tag.starts_with("<script") && attr(tag, "src").is_some() {
            let src = attr(tag, "src").unwrap_or_default();
            let js = assets
                .get(src)
                .ok_or_else(|| format!("The built interface is missing {src}."))?;
            let js = String::from_utf8_lossy(&js).replace("</script", "<\\/script");
            // Scripts go at the end of the body, after the data they read.
            scripts.push(js);
            let close = "</script>";
            let skip = tail[end + 1..]
                .find(close)
                .map_or(end + 1, |c| end + 1 + c + close.len());
            rest = &tail[skip..];
            continue;
        }
        if tag.starts_with("<link") && attr(tag, "rel") == Some("stylesheet") {
            let href = attr(tag, "href").unwrap_or_default();
            let css = assets
                .get(href)
                .ok_or_else(|| format!("The built interface is missing {href}."))?;
            let css = inline_fonts(&String::from_utf8_lossy(&css), assets)
                .replace("</style", "<\\/style");
            out.push_str("<style>");
            out.push_str(&css);
            out.push_str("</style>");
            rest = &tail[end + 1..];
            continue;
        }
        if tag.starts_with("<link")
            && attr(tag, "rel").is_some_and(|r| r.contains("icon") || r.contains("preload"))
        {
            rest = &tail[end + 1..];
            continue;
        }
        if tag.starts_with("<meta")
            && attr(tag, "http-equiv")
                .is_some_and(|v| v.eq_ignore_ascii_case("content-security-policy"))
        {
            // The app's own policy (added by the desktop build) would block
            // the inlined scripts; the export sets its own below.
            rest = &tail[end + 1..];
            continue;
        }
        if tag.starts_with("<head") {
            out.push_str(tag);
            out.push_str(&format!(
                "<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">"
            ));
            rest = &tail[end + 1..];
            continue;
        }
        if tag == "<title>" {
            out.push_str("<title>");
            out.push_str(&escape(title));
            let skip = tail.find("</title>").unwrap_or(end + 1);
            rest = &tail[skip..];
            continue;
        }
        if tag == "</body>" {
            out.push_str("<script>window.__DCA__=");
            out.push_str(&script_json(data));
            out.push_str(";</script>");
            for js in &scripts {
                out.push_str("<script type=\"module\">");
                out.push_str(js);
                out.push_str("</script>");
            }
        }
        out.push_str(tag);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Mem(HashMap<&'static str, &'static str>);
    impl UiAssets for Mem {
        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.0.get(path).map(|s| s.as_bytes().to_vec())
        }
    }

    #[test]
    fn inlines_scripts_styles_fonts_and_data() {
        let assets = Mem(HashMap::from([
            (
                "report.html",
                "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"><title>Benchmark</title><script type=\"module\" crossorigin src=\"/assets/r.js\"></script><link rel=\"stylesheet\" crossorigin href=\"/assets/r.css\"></head><body><div id=\"app\"></div></body></html>",
            ),
            ("/assets/r.js", "console.log('</script>')"),
            ("/assets/r.css", "@font-face{src:url(/assets/inter-latin-wght-normal-1.woff2)}@font-face{src:url(/assets/inter-greek-wght-normal-2.woff2)}"),
            ("/assets/inter-latin-wght-normal-1.woff2", "AB"),
        ]));
        let html = page(
            &assets,
            "report.html",
            "Report <x>",
            &serde_json::json!({"note": "</script><b>"}),
        )
        .unwrap();
        assert!(html.contains("<title>Report &lt;x&gt;</title>"));
        assert!(html.contains("console.log('<\\/script>')"));
        assert!(html.contains("url(data:font/woff2;base64,QUI=)"));
        assert!(html.contains("url(data:font/woff2;base64,)"));
        assert!(html.contains("window.__DCA__={\"note\":\"<\\/script><b>\"}"));
        assert!(!html.contains("src=\"/assets"));
        assert!(!html.contains("default-src 'self'"));
        assert!(html.contains(
            "<head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';"
        ));
        // Data first, then the app that reads it.
        assert!(html.find("__DCA__").unwrap() < html.find("console.log").unwrap());
    }
}
