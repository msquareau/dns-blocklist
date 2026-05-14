use dns_blocklist_compiler::config::SourceEntry;
use dns_blocklist_compiler::validator::{ValidationError, validate_download};

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
