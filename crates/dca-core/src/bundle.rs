//! Opening a bundle: a .zip that holds either a whole assessment folder (as
//! copied from another computer) or what one or more collectors wrote when
//! they ran on their own, for example `Invoke-DCACollect.ps1 -Bundle` on a
//! domain controller. Either way it becomes a new folder in the assessments
//! folder, analyzed when it has no results yet.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::analysis::{self, NewAssessment};
use crate::catalog::Catalog;
use crate::{Error, Result};

/// Refuse archives that would unpack to more than this.
const MAX_UNPACKED: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}

fn bad(zip: &Path, why: impl std::fmt::Display) -> Error {
    Error::Assessment(format!("{} cannot be opened: {why}", zip.display()))
}

/// Unpacks `zip` into `into`, refusing entries that would land outside it.
fn unpack(zip: &Path, into: &Path) -> Result<()> {
    let file = fs::File::open(zip).map_err(io_err(zip))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| bad(zip, e))?;
    if archive.len() > MAX_ENTRIES {
        return Err(bad(zip, format!("it holds more than {MAX_ENTRIES} files")));
    }
    let mut total = 0u64;
    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|e| bad(zip, e))?;
        total = total.saturating_add(entry.size());
        if total > MAX_UNPACKED {
            return Err(bad(zip, "it unpacks to more than 8 GB"));
        }
        if entry.enclosed_name().is_none() {
            return Err(bad(
                zip,
                format!("{} points outside the bundle", entry.name()),
            ));
        }
    }
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| bad(zip, e))?;
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let target = into.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(io_err(&target))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        let mut out = fs::File::create(&target).map_err(io_err(&target))?;
        io::copy(&mut entry, &mut out).map_err(io_err(&target))?;
    }
    Ok(())
}

/// A zip of a folder usually holds that one folder; look inside it.
fn content_root(dir: &Path) -> PathBuf {
    let entries: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    match entries.as_slice() {
        [only] if only.is_dir() => content_root(only),
        _ => dir.to_path_buf(),
    }
}

/// What one collector's `collection.json` says it read.
enum Collected {
    Domain(String),
    Tenant(String),
}

fn collected(dir: &Path) -> Option<Collected> {
    let text = fs::read_to_string(dir.join("collection.json")).ok()?;
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    if v.get("rootdse").is_some() {
        return s("domain").map(|d| Collected::Domain(d.to_ascii_lowercase()));
    }
    if v.get("tenant_id").is_some() {
        return s("tenant").map(|t| Collected::Tenant(t.to_ascii_lowercase()));
    }
    None
}

/// Collector output folders: the root itself or its direct sub-folders.
fn collector_dirs(root: &Path) -> Vec<(PathBuf, Collected)> {
    if let Some(c) = collected(root) {
        return vec![(root.to_path_buf(), c)];
    }
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .map(|r| {
            r.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs.into_iter()
        .filter_map(|d| collected(&d).map(|c| (d, c)))
        .collect()
}

fn unique(root: &Path, name: &str) -> PathBuf {
    let mut dir = root.join(name);
    let mut n = 2;
    while dir.exists() {
        dir = root.join(format!("{name}-{n}"));
        n += 1;
    }
    dir
}

fn stem(zip: &Path) -> String {
    zip.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bundle".into())
}

/// Imports `zip` into the assessments folder `root` and returns the new
/// assessment's folder.
pub fn import(zip: &Path, root: &Path, catalog: &Catalog, now: i64) -> Result<PathBuf> {
    fs::create_dir_all(root).map_err(io_err(root))?;
    let staging = unique(root, &format!(".import-{now}"));
    fs::create_dir_all(&staging).map_err(io_err(&staging))?;
    let outcome = unpack(zip, &staging).and_then(|()| place(zip, &staging, root, catalog, now));
    let _ = fs::remove_dir_all(&staging);
    outcome
}

fn place(zip: &Path, staging: &Path, root: &Path, catalog: &Catalog, now: i64) -> Result<PathBuf> {
    let content = content_root(staging);

    // A whole assessment folder.
    if content.join("manifest.json").is_file() {
        let name = if content == staging {
            stem(zip)
        } else {
            content
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| stem(zip))
        };
        let dir = unique(root, &name);
        fs::rename(&content, &dir).map_err(io_err(&dir))?;
        if !dir.join("results.json").is_file() {
            if let Err(e) = analysis::analyze(&dir, catalog) {
                let _ = fs::remove_dir_all(&dir);
                return Err(e);
            }
        }
        return Ok(dir);
    }

    // Output of collectors that ran on their own.
    let found = collector_dirs(&content);
    if found.is_empty() {
        return Err(bad(
            zip,
            "it holds neither a Benchmark assessment nor collector output (no manifest.json or collection.json)",
        ));
    }
    let mut domains = Vec::new();
    let mut tenant = None;
    for (_, c) in &found {
        match c {
            Collected::Domain(d) if !domains.contains(d) => domains.push(d.clone()),
            Collected::Tenant(t) if tenant.is_none() => tenant = Some(t.clone()),
            Collected::Tenant(t) if tenant.as_ref() != Some(t) => {
                return Err(bad(zip, "it holds more than one tenant"));
            }
            _ => {}
        }
    }
    let dir = analysis::create(
        root,
        NewAssessment {
            name: Some(stem(zip)),
            domains,
            tenant,
            areas: Vec::new(),
        },
        now,
    )?;
    let moved = found.into_iter().try_for_each(|(src, c)| {
        let target = match &c {
            Collected::Domain(d) => analysis::ad_raw_dir(&dir, d),
            Collected::Tenant(t) => analysis::entra_raw_dir(&dir, t),
        };
        if target.exists() {
            return Err(bad(zip, "it holds the same domain twice"));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        fs::rename(&src, &target).map_err(io_err(&target))
    });
    if let Err(e) = moved.and_then(|()| analysis::analyze(&dir, catalog).map(|_| ())) {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::results::tests::catalog;

    fn zip_dir(src: &Path, zip_path: &Path, prefix: &str) {
        let file = fs::File::create(zip_path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        let mut stack = vec![src.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let rel = p
                    .strip_prefix(src)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                w.start_file(format!("{prefix}{rel}"), opts).unwrap();
                w.write_all(&fs::read(&p).unwrap()).unwrap();
            }
        }
        w.finish().unwrap();
    }

    #[test]
    fn imports_standalone_collector_output_and_analyzes_it() {
        let src = tempfile::tempdir().unwrap();
        crate::ad::tests::write_domain(src.path(), true);
        let work = tempfile::tempdir().unwrap();
        let zip = work.path().join("dc01-corp.zip");
        zip_dir(src.path(), &zip, "");
        let root = work.path().join("assessments");

        let dir = import(&zip, &root, &catalog(), 1_791_280_000).unwrap();
        assert!(dir.join("results.json").is_file());
        let a = crate::results::Assessment::load(&dir).unwrap();
        assert_eq!(a.name, "dc01-corp");
        assert_eq!(a.manifest.scope.domains, ["corp.example.com"]);
        // The staging folder is gone.
        let left: Vec<String> = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");

        // A copy of that assessment folder, zipped inside its own folder,
        // opens as a second assessment without analyzing again.
        let again = work.path().join("copy.zip");
        zip_dir(&dir, &again, "october/");
        let second = import(&again, &root, &catalog(), 1_791_280_100).unwrap();
        assert_eq!(second.file_name().unwrap(), "october");
        assert!(second.join("results.json").is_file());
    }

    #[test]
    fn refuses_unknown_content_and_cleans_up() {
        let work = tempfile::tempdir().unwrap();
        let zip = work.path().join("notes.zip");
        let mut w = zip::ZipWriter::new(fs::File::create(&zip).unwrap());
        w.start_file("readme.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"hello").unwrap();
        w.finish().unwrap();
        let root = work.path().join("assessments");
        let err = import(&zip, &root, &catalog(), 1).unwrap_err().to_string();
        assert!(err.contains("neither"), "{err}");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn refuses_entries_outside_the_bundle() {
        let work = tempfile::tempdir().unwrap();
        let zip = work.path().join("evil.zip");
        let mut w = zip::ZipWriter::new(fs::File::create(&zip).unwrap());
        w.start_file("../escape.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
        let root = work.path().join("assessments");
        let err = import(&zip, &root, &catalog(), 1).unwrap_err().to_string();
        assert!(err.contains("outside"), "{err}");
        assert!(!work.path().join("escape.txt").exists());
    }
}
