use dns_blocklist_compiler::config::SourceEntry;
use dns_blocklist_compiler::parser::{DomainStore, extract_expected_entry_count};
use dns_blocklist_compiler::validator::{
    Canary, ValidationError, validate_download, validate_output, validate_parse,
};
use dns_blocklist_compiler::{binary, validator};

fn source_with_floors(format: &str, min_size: Option<usize>) -> SourceEntry {
    SourceEntry {
        category: "adsTrackersUltimate".into(),
        category_index: 4,
        file: "ultimate.txt".into(),
        base_url: "domains".into(),
        format: format.into(),
        display_name: "HaGeZi Ultimate (test)".into(),
        min_size_bytes: min_size,
        min_parsed_entries: None,
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
        min_parsed_entries: None,
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

fn source_with_parse_floor(min_parsed: Option<usize>) -> SourceEntry {
    SourceEntry {
        category: "adsTrackersUltimate".into(),
        category_index: 4,
        file: "ultimate.txt".into(),
        base_url: "domains".into(),
        format: "domains".into(),
        display_name: "HaGeZi Ultimate (test)".into(),
        min_size_bytes: None,
        min_parsed_entries: min_parsed,
        min_trie_entries: None,
    }
}

#[test]
fn parse_ratio_below_90_percent_is_regression() {
    let src = source_with_parse_floor(None);
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
    let src = source_with_parse_floor(None);
    // 0.9 * 100000 = 90000 exactly
    validate_parse(90_000, Some(100_000), &src).unwrap();
}

#[test]
fn parse_ratio_just_below_90_percent_fails() {
    let src = source_with_parse_floor(None);
    let err = validate_parse(89_999, Some(100_000), &src).unwrap_err();
    assert!(matches!(err, ValidationError::CountRegression { .. }));
}

#[test]
fn min_parsed_entries_floor_applies_when_no_upstream_header() {
    let src = source_with_parse_floor(Some(1000));
    let err = validate_parse(500, None, &src).unwrap_err();
    match err {
        ValidationError::BelowFloor { parsed, min, .. } => {
            assert_eq!(parsed, 500);
            assert_eq!(min, 1000);
        }
        other => panic!("expected BelowFloor, got {other:?}"),
    }
}

#[test]
fn min_parsed_entries_floor_also_applies_with_upstream_header() {
    // Both checks apply: ratio passes (95000 / 100000 = 95%), but absolute floor fails.
    let src = source_with_parse_floor(Some(150_000));
    let err = validate_parse(95_000, Some(100_000), &src).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::BelowFloor { min: 150_000, .. }
    ));
}

#[test]
fn parse_unconstrained_zero_still_fails() {
    let src = source_with_parse_floor(None);
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
        min_parsed_entries: None,
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
