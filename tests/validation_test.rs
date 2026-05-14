use dns_blocklist_compiler::config::SourceEntry;
use dns_blocklist_compiler::parser::extract_expected_entry_count;
use dns_blocklist_compiler::validator::{ValidationError, validate_download, validate_parse};

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
