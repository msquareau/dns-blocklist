//! The previous run's parsed count per source.
//!
//! The file lives beside the run that writes it and the CI cache carries it
//! between runs. It exists only to raise a warning, so both directions fail
//! open: a run with no baseline behaves exactly like a run whose counts all
//! held steady.

use std::collections::BTreeMap;
use std::path::Path;

/// Read the baseline.
///
/// A missing or unreadable file reads as an empty map on purpose. The baseline
/// must never be able to fail a build of its own accord.
pub fn read(path: &Path) -> BTreeMap<String, usize> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Write the baseline.
///
/// A write error prints a warning and returns. It never aborts the run.
///
/// The write goes to a temporary file in the same directory, then renames
/// over the target. A job cancelled mid-write leaves the temporary file
/// truncated, not the baseline the CI cache stores — the target either keeps
/// its previous contents or gets the new ones whole, never a half-written
/// mix. `read` already fails open, so a cancelled write costs one baseline
/// refresh, not a corrupt one.
pub fn write(path: &Path, counts: &BTreeMap<String, usize>) {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "WARN: could not create the baseline directory {}: {e}",
            parent.display()
        );
        return;
    }
    let json = match serde_json::to_string_pretty(counts) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("WARN: could not serialize the source-count baseline: {e}");
            return;
        }
    };
    let tmp_path = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp_path, json) {
        eprintln!(
            "WARN: could not record the source-count baseline at {}: {e}",
            tmp_path.display()
        );
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        eprintln!(
            "WARN: could not install the source-count baseline at {}: {e}",
            path.display()
        );
        let _ = std::fs::remove_file(&tmp_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("sdbl-counts-test-{}-{}", std::process::id(), name));
        p
    }

    #[test]
    fn a_missing_baseline_reads_as_empty() {
        let path = temp_path("missing/source-counts.json");
        assert!(read(&path).is_empty());
    }

    #[test]
    fn an_unparseable_baseline_reads_as_empty() {
        let path = temp_path("garbage.json");
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(read(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_written_baseline_reads_back() {
        let path = temp_path("roundtrip/source-counts.json");
        let mut counts = BTreeMap::new();
        counts.insert("HaGeZi Light".to_string(), 65681usize);
        counts.insert("HaGeZi Multi".to_string(), 546182usize);
        write(&path, &counts);
        assert_eq!(read(&path), counts);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_write_to_an_impossible_path_does_not_panic() {
        let counts: BTreeMap<String, usize> = BTreeMap::new();
        write(
            std::path::Path::new("/dev/null/nope/source-counts.json"),
            &counts,
        );
    }
}
