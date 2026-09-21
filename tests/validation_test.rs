use dns_blocklist_compiler::config::SourceEntry;
use dns_blocklist_compiler::parser::{DomainStore, extract_expected_entry_count};
use dns_blocklist_compiler::run::{ReportInputs, RunStatus, build_validation_report};
use dns_blocklist_compiler::validator::{
    Canary, ValidationError, validate_download, validate_output, validate_parse,
};
use dns_blocklist_compiler::{binary, counts, validator};

fn source_with_floors(format: &str, min_size: Option<usize>) -> SourceEntry {
    SourceEntry {
        category: "adsTrackersUltimate".into(),
        category_index: 4,
        file: "ultimate.txt".into(),
        base_url: "domains".into(),
        format: format.into(),
        display_name: "HaGeZi Ultimate (test)".into(),
        min_size_bytes: min_size,
        min_trie_entries: None,
    }
}

#[test]
fn rejects_http_404() {
    let src = source_with_floors("domains", None);
    let err = validate_download(404, Some("text/plain"), "anything\n", &src).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::HttpStatus { status: 404, .. }
    ));
}

#[test]
fn rejects_http_500() {
    let src = source_with_floors("domains", None);
    let err = validate_download(500, Some("text/plain"), "anything\n", &src).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::HttpStatus { status: 500, .. }
    ));
}

#[test]
fn rejects_body_below_min_size() {
    let src = source_with_floors("domains", Some(13_500_000));
    // 199-byte body — the exact symptom from issue #20's evidence table for nrd7.txt
    let tiny_body = "example.com\n".repeat(20); // ~240 bytes, still way below 13.5M
    let err =
        validate_download(200, Some("text/plain; charset=utf-8"), &tiny_body, &src).unwrap_err();
    match err {
        ValidationError::TooSmall { actual, min, .. } => {
            assert!(actual < min);
            assert_eq!(min, 13_500_000);
        }
        other => panic!("expected TooSmall, got {other:?}"),
    }
}

#[test]
fn rejects_text_html_content_type() {
    let src = source_with_floors("domains", None);
    // jsDelivr serves text/html for missing files
    let html_body = "<html><body>Not Found</body></html>".repeat(100);
    let err =
        validate_download(200, Some("text/html; charset=utf-8"), &html_body, &src).unwrap_err();
    assert!(matches!(err, ValidationError::BadContentType { .. }));
}

#[test]
fn rejects_application_json_content_type() {
    let src = source_with_floors("domains", None);
    let body = r#"{"error": "not found"}"#.repeat(50);
    let err = validate_download(200, Some("application/json"), &body, &src).unwrap_err();
    assert!(matches!(err, ValidationError::BadContentType { .. }));
}

#[test]
fn accepts_text_plain_with_charset() {
    let src = source_with_floors("domains", None);
    let body = "example.com\ntest.org\nblocked.net\n";
    validate_download(200, Some("text/plain; charset=utf-8"), body, &src).unwrap();
}

#[test]
fn accepts_when_content_type_missing() {
    // Hagezi via raw.githubusercontent.com sometimes omits Content-Type
    let src = source_with_floors("domains", None);
    let body = "example.com\ntest.org\n";
    validate_download(200, None, body, &src).unwrap();
}

#[test]
fn rejects_html_error_page_via_smell_test() {
    let src = source_with_floors("domains", None);
    // Big enough body but no parseable domains
    let html = "<html>\n<body>\n<h1>404 Not Found</h1>\n<p>The requested file is unavailable.</p>\n</body>\n</html>\n".repeat(20);
    let err = validate_download(200, None, &html, &src).unwrap_err();
    assert!(matches!(err, ValidationError::NotADomainList { .. }));
}

#[test]
fn accepts_healthy_domains_format() {
    let src = source_with_floors("domains", Some(50));
    let body = "\
# HaGeZi DNS Blocklists
# Title: Ads & Trackers (Light)
# Version: 2026.05.14
# Last modified: Wed, 14 May 2026 04:00:00 +0000
# Expires: 1 day
# Source: https://github.com/hagezi/dns-blocklists
# Number of entries: 4
0--cdn.example.com
doubleclick.net
google-analytics.com
googletagmanager.com
";
    validate_download(200, Some("text/plain; charset=utf-8"), body, &src).unwrap();
}

#[test]
fn accepts_healthy_adblock_format() {
    let src = SourceEntry {
        category: "malwarePhishing".into(),
        category_index: 8,
        file: "fake.txt".into(),
        base_url: "adblock".into(),
        format: "adblock".into(),
        display_name: "HaGeZi Fake/Phishing".into(),
        min_size_bytes: Some(50),
        min_trie_entries: None,
    };
    let body = "\
! HaGeZi Fake/Phishing
! Number of entries: 3
||scam.example.com^
||phishing.example.org^
||fakebank.example.net^
";
    validate_download(200, Some("text/plain"), body, &src).unwrap();
}

#[test]
fn parse_ratio_below_90_percent_is_regression() {
    let src = source_with_floors("domains", None);
    // declared 657403, parsed 1 — the exact issue-#20 symptom
    let err = validate_parse(1, Some(657403), &src).unwrap_err();
    match err {
        ValidationError::CountRegression {
            parsed, expected, ..
        } => {
            assert_eq!(parsed, 1);
            assert_eq!(expected, 657403);
        }
        other => panic!("expected CountRegression, got {other:?}"),
    }
}

#[test]
fn parse_ratio_at_exact_90_percent_passes() {
    let src = source_with_floors("domains", None);
    // 0.9 * 100000 = 90000 exactly
    validate_parse(90_000, Some(100_000), &src).unwrap();
}

#[test]
fn parse_ratio_just_below_90_percent_fails() {
    let src = source_with_floors("domains", None);
    let err = validate_parse(89_999, Some(100_000), &src).unwrap_err();
    assert!(matches!(err, ValidationError::CountRegression { .. }));
}

#[test]
fn parse_unconstrained_zero_still_fails() {
    let src = source_with_floors("domains", None);
    let err = validate_parse(0, None, &src).unwrap_err();
    assert!(matches!(err, ValidationError::BelowFloor { parsed: 0, .. }));
}

#[test]
fn extract_expected_entry_count_recognises_hagezi_ultimate_header() {
    let content = "\
# Title: HaGeZi's Ultimate DNS Blocklist
# Number of entries: 657403
# -----------------------------------------------------------
doubleclick.net
";
    assert_eq!(extract_expected_entry_count(content), Some(657403));
}

#[test]
fn extract_expected_entry_count_returns_none_for_files_without_header() {
    let content = "# A bare list with no entry count\nexample.com\n";
    assert_eq!(extract_expected_entry_count(content), None);
}

// ============================================================
// Layer 3 — round-trip + canary + per-bit floor
// ============================================================

fn source_with_trie_floor(category_index: u8, min_trie: Option<usize>) -> SourceEntry {
    SourceEntry {
        category: format!("cat{category_index}"),
        category_index,
        file: "x.txt".into(),
        base_url: "domains".into(),
        format: "domains".into(),
        display_name: format!("Source {category_index}"),
        min_size_bytes: None,
        min_trie_entries: min_trie,
    }
}

fn doubleclick_canary() -> Canary {
    Canary {
        domain: "doubleclick.net".into(),
        expected_min_bitmap: (1u32 << 3) | (1u32 << 4),
        rationale: "test".into(),
    }
}

#[test]
fn canary_check_passes_when_both_required_bits_are_present() {
    let mut store = DomainStore::new();
    store.add_exact("doubleclick.net", 3);
    store.add_exact("doubleclick.net", 4);
    let cats = vec![
        ("adsTrackersProPlus".into(), 3u8),
        ("adsTrackersUltimate".into(), 4u8),
    ];
    let data = binary::compile(&store, &cats);

    let errors = validate_output(&data, &[doubleclick_canary()], &[], &store, 100);
    assert!(
        errors.is_empty(),
        "expected no validation errors, got: {errors:?}"
    );
}

#[test]
fn canary_check_catches_issue_20_symptom() {
    // Simulate exactly the regression from issue #20: ultimate.txt content
    // never made it into the trie, so doubleclick.net has bit 3 (pro.plus)
    // but not bit 4 (ultimate).
    let mut store = DomainStore::new();
    store.add_exact("doubleclick.net", 3);
    // Intentionally NOT adding bit 4 — this is the bug.
    let cats = vec![
        ("adsTrackersProPlus".into(), 3u8),
        ("adsTrackersUltimate".into(), 4u8),
    ];
    let data = binary::compile(&store, &cats);

    let errors = validate_output(&data, &[doubleclick_canary()], &[], &store, 100);
    assert_eq!(
        errors.len(),
        1,
        "expected one canary failure, got {errors:?}"
    );
    match &errors[0] {
        ValidationError::CanaryMissing { domain, want, got } => {
            assert_eq!(domain, "doubleclick.net");
            assert_eq!(*want, (1u32 << 3) | (1u32 << 4));
            // bit 3 set, bit 4 missing
            assert_eq!(*got, 1u32 << 3);
        }
        other => panic!("expected CanaryMissing, got {other:?}"),
    }
}

#[test]
fn per_bit_floor_catches_undersized_category() {
    let mut store = DomainStore::new();
    // Only 1 entry tagged with bit 4
    store.add_exact("doubleclick.net", 4);
    let cats = vec![("adsTrackersUltimate".into(), 4u8)];
    let data = binary::compile(&store, &cats);

    let src = source_with_trie_floor(4, Some(100));
    let errors = validate_output(&data, &[], std::slice::from_ref(&src), &store, 100);
    assert_eq!(
        errors.len(),
        1,
        "expected one floor failure, got {errors:?}"
    );
    match &errors[0] {
        ValidationError::TrieEntriesBelowFloor {
            bit, count, min, ..
        } => {
            assert_eq!(*bit, 4);
            assert_eq!(*count, 1);
            assert_eq!(*min, 100);
        }
        other => panic!("expected TrieEntriesBelowFloor, got {other:?}"),
    }
}

#[test]
fn round_trip_sample_matches_for_healthy_store() {
    // Build a store with a few hundred domains, compile, and confirm every
    // sampled lookup returns the same bitmap.
    let mut store = DomainStore::new();
    for i in 0..200 {
        let domain = format!("host-{i:04}.example.com");
        store.add_exact(&domain, (i % 16) as u8);
    }
    let cats: Vec<(String, u8)> = (0..16).map(|i| (format!("cat{i}"), i as u8)).collect();
    let data = binary::compile(&store, &cats);

    let errors = validate_output(&data, &[], &[], &store, 200);
    assert!(
        errors.is_empty(),
        "healthy store should round-trip cleanly, got: {errors:?}"
    );
}

#[test]
fn empty_canary_list_does_not_fail_build() {
    let mut store = DomainStore::new();
    store.add_exact("any.example.com", 0);
    let cats = vec![("cat0".into(), 0u8)];
    let data = binary::compile(&store, &cats);

    let errors = validate_output(&data, &[], &[], &store, 100);
    assert!(errors.is_empty());
}

#[test]
fn load_canaries_reads_the_repo_root_file() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("canary-domains.json");
    let canaries = validator::load_canaries(&path).expect("repo root canary file should parse");
    assert!(
        canaries.iter().any(|c| c.domain == "doubleclick.net"),
        "doubleclick.net must remain in the canary list — it is the issue-#20 regression canary"
    );
    let dc = canaries
        .iter()
        .find(|c| c.domain == "doubleclick.net")
        .unwrap();
    assert!(
        dc.expected_min_bitmap & (1u32 << 4) != 0,
        "doubleclick canary must require Ultimate bit 4"
    );
}

#[test]
fn category_stats_reflect_trie_occupancy_not_parse_lines() {
    // Older semantics: categoryStats = "lines parsed for this source", which
    // double-counts case-insensitive duplicates and per-issue-#20 misrepresents
    // what consumers actually want (how many unique domains carry the bit).
    //
    // Build via parse_blocklist with 3 case-variant inputs that resolve to the
    // same domain. parse returns 3 lines processed, but the trie holds 1.
    use dns_blocklist_compiler::parser::parse_blocklist;
    use dns_blocklist_compiler::reader;
    let content = "EXAMPLE.com\nexample.com\nExample.Com\n";
    let mut store = DomainStore::new();
    let (exact_lines, _) = parse_blocklist(content, "domains", 0, &mut store);
    assert_eq!(exact_lines, 3, "parser counts all three input lines");

    let cats = vec![("cat0".into(), 0u8)];
    let data = binary::compile(&store, &cats);
    let header = reader::parse_header(&data).unwrap();
    let counts = reader::count_entries_per_bit(&data, header.exact_trie_offset as usize);
    assert_eq!(
        counts[0], 1,
        "trie should contain one entry for bit 0 (the 3 inputs all dedup case-insensitively)"
    );
}

#[test]
fn the_issue_20_symptom_exactly_199_bytes() {
    // Re-create the exact symptom: HTTP 200 with a tiny body for a list that
    // should be megabytes. This is the regression that issue #20 documents
    // shipping in production.
    let src = source_with_floors("domains", Some(13_500_000));
    let body = "a".repeat(199);
    let err = validate_download(200, Some("text/plain"), &body, &src).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::TooSmall {
            actual: 199,
            min: 13_500_000,
            ..
        }
    ));
}

// ============================================================
// The degraded-run wiring — spec §9's central promise, exercised end to end
// through the library items `main` orchestrates rather than owns.
// ============================================================

#[test]
fn a_70_percent_parse_drop_leaves_the_run_status_at_exit_code_zero() {
    let src = source_with_floors("domains", None);
    let mut degraded: Vec<ValidationError> = Vec::new();
    if let Some(e) = validator::check_parse_drop(&src, 30_000, Some(100_000), 0.6) {
        degraded.push(e);
    }
    assert_eq!(
        degraded.len(),
        1,
        "a 70% fall against the baseline must produce exactly one ParsedDrop"
    );
    assert!(matches!(degraded[0], ValidationError::ParsedDrop { .. }));

    // Mirrors main's status derivation: a non-empty degraded list is
    // Degraded, never Failed — the run still publishes.
    let status = if degraded.is_empty() {
        RunStatus::Ok
    } else {
        RunStatus::Degraded
    };
    assert_eq!(status, RunStatus::Degraded);
    assert_eq!(status.exit_code(), 0);
}

#[test]
fn a_source_that_drops_and_loses_its_header_together_stays_at_exit_code_zero_with_one_entry() {
    use dns_blocklist_compiler::counts::SourceBaseline;

    let src = source_with_floors("domains", None);
    let baseline = SourceBaseline {
        parsed: 100_000,
        declared_count_seen: true,
    };
    let mut degraded: Vec<ValidationError> = Vec::new();
    // Both check_parse_drop and check_missing_declared_count would fire
    // independently on this input (a 70% fall, and no count declared this
    // run against a baseline that had one) — check_parse_degraded must
    // still record only one entry, and it must never reach the failure list.
    if let Some(e) = validator::check_parse_degraded(&src, 30_000, None, Some(&baseline), 0.6) {
        degraded.push(e);
    }
    assert_eq!(
        degraded.len(),
        1,
        "a simultaneous drop and header loss must report as one degraded entry, not two"
    );
    assert!(matches!(degraded[0], ValidationError::ParsedDrop { .. }));

    let status = if degraded.is_empty() {
        RunStatus::Ok
    } else {
        RunStatus::Degraded
    };
    assert_eq!(status, RunStatus::Degraded);
    assert_eq!(status.exit_code(), 0);
}

#[test]
fn the_report_shows_a_degraded_section_when_something_degraded() {
    let store = DomainStore::new();
    let degraded = vec![ValidationError::ParsedDrop {
        source: "Test Source".into(),
        parsed: 30_000,
        previous: 100_000,
    }];
    let report = build_validation_report(&ReportInputs {
        build_id: "test-build",
        status: RunStatus::Degraded,
        total_sources: 1,
        store: &store,
        source_lines: &[],
        category_stats: &[],
        canaries: &[],
        degraded: &degraded,
    });
    assert!(report.contains("Status: degraded"));
    assert!(report.contains("=== Degraded ==="));
    assert!(report.contains("Final status: degraded"));
}

#[test]
fn the_report_omits_the_degraded_section_when_nothing_degraded() {
    let store = DomainStore::new();
    let degraded: Vec<ValidationError> = Vec::new();
    let report = build_validation_report(&ReportInputs {
        build_id: "test-build",
        status: RunStatus::Ok,
        total_sources: 1,
        store: &store,
        source_lines: &[],
        category_stats: &[],
        canaries: &[],
        degraded: &degraded,
    });
    assert!(!report.contains("=== Degraded ==="));
    assert!(!report.to_lowercase().contains("degraded"));
    assert!(report.trim_end().ends_with("Final status: ok"));
}

#[test]
fn every_configured_source_has_a_unique_display_name_and_category_index() {
    // displayName is the baseline's primary key (src/counts.rs) and
    // categoryIndex selects the bit each per-bit floor is checked against
    // (validator::validate_output). Two sources sharing either would each be
    // satisfied by the other's entries, and neither guard would ever fire.
    let config =
        dns_blocklist_compiler::config::load_config(std::path::Path::new("blocklist-sources.json"))
            .expect("the shipped config must load");

    let mut seen_names = std::collections::HashSet::new();
    for source in &config.sources {
        assert!(
            seen_names.insert(source.display_name.clone()),
            "duplicate displayName: {}",
            source.display_name
        );
    }

    let mut seen_indices = std::collections::HashSet::new();
    for source in &config.sources {
        assert!(
            seen_indices.insert(source.category_index),
            "duplicate categoryIndex {} on {}",
            source.category_index,
            source.display_name
        );
    }
}

#[test]
fn every_configured_source_sets_both_floors() {
    let config =
        dns_blocklist_compiler::config::load_config(std::path::Path::new("blocklist-sources.json"))
            .expect("the shipped config must load");
    for source in &config.sources {
        assert!(
            source.min_size_bytes.unwrap_or(0) > 0,
            "{} has no minSizeBytes",
            source.display_name
        );
        assert!(
            source.min_trie_entries.unwrap_or(0) > 0,
            "{} has no minTrieEntries",
            source.display_name
        );
    }
}

// Property 1, proven through the real persistence path.
//
// `property_1_a_source_that_never_declares_a_count_stays_silent_forever` in
// src/validator.rs hand-builds its second- and later-run `SourceBaseline`
// with a helper, so it only shows that the guard is correct given a
// `declared_count_seen: false` value — it never shows that `counts::write`
// followed by `counts::read` actually produces that value. The persistence
// layer is exactly where this class of bug hid before: the effect only
// appeared from the second run onward, once a baseline had actually been
// written and read back. This test drives `counts::write`/`counts::read`
// for real, across three simulated runs, so the round trip itself is under
// test, not assumed.
#[test]
fn a_source_with_no_header_stays_silent_across_a_real_baseline_round_trip() {
    let src = source_with_floors("domains", None);
    let path = std::env::temp_dir().join(format!(
        "sdbl-validation-test-no-header-baseline-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    // Run 1: no baseline file exists yet at all.
    let run1_baseline = counts::read(&path);
    assert!(run1_baseline.is_empty());
    assert!(
        validator::check_missing_declared_count(&src, None, run1_baseline.get(&src.display_name))
            .is_none()
    );

    // Run 1 completes. main.rs records a baseline entry for every source
    // that downloads and parses, header or not — built here exactly the
    // way main.rs builds it, from an `expected` that is `None`.
    let expected: Option<usize> = None;
    let mut run1_counts = counts::Baseline::new();
    run1_counts.insert(
        src.display_name.clone(),
        counts::SourceBaseline {
            parsed: 12_345,
            declared_count_seen: expected.is_some(),
        },
    );
    counts::write(&path, &run1_counts);

    // Run 2: read the baseline back off disk — this is the value that
    // actually survived a real serialize-and-deserialize, not a hand-built
    // stand-in for it.
    let run2_baseline = counts::read(&path);
    assert!(
        validator::check_missing_declared_count(&src, None, run2_baseline.get(&src.display_name))
            .is_none()
    );

    // Run 3: read it again. The guard must stay silent indefinitely, not
    // just on the first read after the write.
    let run3_baseline = counts::read(&path);
    assert!(
        validator::check_missing_declared_count(&src, None, run3_baseline.get(&src.display_name))
            .is_none()
    );

    let _ = std::fs::remove_file(&path);
}
