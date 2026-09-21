//! The previous run's baseline per source.
//!
//! The file lives beside the run that writes it and the CI cache carries it
//! between runs. It exists only to raise a warning, so both directions fail
//! open: a run with no baseline behaves exactly like a run whose counts all
//! held steady.
//!
//! Each entry carries two facts, not one: the parsed-line count, and whether
//! an upstream-declared entry count was actually seen for that source this
//! run. `parsed` alone is not evidence a header was ever declared — it is
//! written for every source that downloads and parses, header or no header.
//! `declared_count_seen` is the only honest signal that a source once
//! carried a count, and it is what `check_missing_declared_count` needs to
//! avoid flagging a source that never declared one in the first place.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// One source's recorded state from the previous run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBaseline {
    /// The number of lines the parser produced for this source.
    pub parsed: usize,
    /// Whether `extract_expected_entry_count` found a declared count for
    /// this source that run. `false` covers both "no header, as designed"
    /// and "header present but not parseable" — either way there is no
    /// count to compare against, so there is nothing to have lost.
    pub declared_count_seen: bool,
}

/// The full baseline: one entry per source, keyed by `displayName`.
pub type Baseline = BTreeMap<String, SourceBaseline>;

/// Read the baseline.
///
/// A missing, unreadable, or wrong-shaped file reads as an empty map on
/// purpose — including a file written by a previous, older version of this
/// module in a different shape. The baseline must never be able to fail a
/// build of its own accord; the cost of misreading it is one silent run and
/// a rewrite in the current format, never a panic and never an abort.
pub fn read(path: &Path) -> Baseline {
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
pub fn write(path: &Path, counts: &Baseline) {
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

    /// Property 4: a baseline written by the pre-rebaseline module —
    /// `BTreeMap<String, usize>`, no `declared_count_seen` — must not panic
    /// the reader and must not fail the build. It is a shape mismatch, not
    /// corrupt JSON, so it exercises a different path than
    /// `an_unparseable_baseline_reads_as_empty` above. Reading it as empty is
    /// correct: one silent run, then a rewrite in the new format.
    #[test]
    fn an_old_format_baseline_reads_as_empty_without_panicking() {
        let path = temp_path("old-format.json");
        std::fs::write(&path, br#"{"HaGeZi Light": 65681, "HaGeZi Multi": 546182}"#).unwrap();
        assert!(read(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_written_baseline_reads_back() {
        let path = temp_path("roundtrip/source-counts.json");
        let mut counts = Baseline::new();
        counts.insert(
            "HaGeZi Light".to_string(),
            SourceBaseline {
                parsed: 65681,
                declared_count_seen: true,
            },
        );
        counts.insert(
            "HaGeZi Multi".to_string(),
            SourceBaseline {
                parsed: 546182,
                declared_count_seen: true,
            },
        );
        counts.insert(
            "NRD Feed (no header)".to_string(),
            SourceBaseline {
                parsed: 900,
                declared_count_seen: false,
            },
        );
        write(&path, &counts);
        assert_eq!(read(&path), counts);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_write_to_an_impossible_path_does_not_panic() {
        let counts: Baseline = Baseline::new();
        write(
            std::path::Path::new("/dev/null/nope/source-counts.json"),
            &counts,
        );
    }
}
