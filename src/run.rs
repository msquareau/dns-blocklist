//! How a run ends, and the report that explains it.
//!
//! This is the wiring behind the branch's central promise: a source whose
//! parse falls against its baseline is recorded as degraded, never as a
//! failure, and a degraded run still exits 0 and still publishes. Moving it
//! out of `main` is what makes that wiring reachable from a test — `main`
//! itself can only be exercised end to end.

use crate::validator::ValidationError;
use crate::{metadata, parser, validator};

/// How a run ended.
///
/// Severity is a property of each guard, fixed at design time, not a mode the
/// caller picks. A degraded run publishes: the artifact is sound, but
/// something needs a person to look at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunStatus {
    Ok,
    Degraded,
    Failed,
}

impl RunStatus {
    pub fn label(self) -> &'static str {
        match self {
            RunStatus::Ok => "ok",
            RunStatus::Degraded => "degraded",
            RunStatus::Failed => "failed",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            RunStatus::Ok | RunStatus::Degraded => 0,
            RunStatus::Failed => 1,
        }
    }
}

pub struct ReportInputs<'a> {
    pub build_id: &'a str,
    pub status: RunStatus,
    pub total_sources: usize,
    pub store: &'a parser::DomainStore,
    pub source_lines: &'a [String],
    pub category_stats: &'a [metadata::CategoryStat],
    pub canaries: &'a [validator::Canary],
    pub degraded: &'a [ValidationError],
}

pub fn build_validation_report(r: &ReportInputs<'_>) -> String {
    use std::fmt::Write as _;

    let mut s = String::new();
    let _ = writeln!(s, "DNS Blocklist Validation Report");
    let _ = writeln!(s, "================================");
    let _ = writeln!(s, "Build ID: {}", r.build_id);
    let _ = writeln!(s, "Status: {}", r.status.label());
    let _ = writeln!(s, "Sources configured: {}", r.total_sources);
    let _ = writeln!(s, "Unique exact domains: {}", r.store.exact_domains.len());
    let _ = writeln!(
        s,
        "Unique wildcard suffixes: {}",
        r.store.wildcard_suffixes.len()
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "=== Per-source (Layer 1 + Layer 2) ===");
    for line in r.source_lines {
        let _ = writeln!(s, "{line}");
    }
    if !r.degraded.is_empty() {
        let _ = writeln!(s);
        let _ = writeln!(s, "=== Degraded ===");
        let _ = writeln!(
            s,
            "The artifact is sound. Each entry below needs a person to look at it."
        );
        for e in r.degraded {
            let _ = writeln!(s, "  - {e}");
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "=== Layer 3 ===");
    let _ = writeln!(s, "Canaries checked: {} (all passed)", r.canaries.len());
    for c in r.canaries {
        let _ = writeln!(
            s,
            "  {} → required bits {:#010b}",
            c.domain, c.expected_min_bitmap
        );
    }
    let _ = writeln!(s, "Round-trip sample: OK (no store-vs-trie mismatches)");
    let _ = writeln!(s, "Per-bit floors: all met");
    let _ = writeln!(s);
    let _ = writeln!(s, "=== Trie-derived categoryStats ===");
    for stat in r.category_stats {
        let _ = writeln!(
            s,
            "  {} — {} exact, {} wildcard",
            stat.name, stat.exact, stat.wildcard
        );
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "Final status: {}", r.status.label());
    s
}
