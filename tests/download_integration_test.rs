mod common;

use common::binary_reader;
use dns_blocklist_compiler::{binary, config, downloader, parser};
use std::collections::HashMap;

/// Build a minimal SourcesConfig with a single source for testing.
fn single_source_config(
    category: &str,
    category_index: u8,
    file: &str,
    base_url_key: &str,
    base_url_value: &str,
    format: &str,
) -> config::SourcesConfig {
    let mut base_urls = HashMap::new();
    base_urls.insert(base_url_key.to_string(), base_url_value.to_string());

    config::SourcesConfig {
        version: 1,
        description: "Integration test".to_string(),
        base_urls,
        sources: vec![config::SourceEntry {
            category: category.to_string(),
            category_index,
            file: file.to_string(),
            base_url: base_url_key.to_string(),
            format: format.to_string(),
            display_name: format!("Test {}", category),
        }],
    }
}

/// Download a single source → parse → compile → verify header + lookups.
///
/// Uses HaGeZi Apple Tracking (domains format, ~105 domains, category 13).
#[test]
#[ignore]
fn test_download_and_compile_domains_format() {
    let cfg = single_source_config(
        "appleTracker",
        13,
        "native.apple.txt",
        "domains",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains",
        "domains",
    );

    // Download
    let results = downloader::download_all(&cfg);
    assert_eq!(results.len(), 1);
    let content = results[0]
        .content
        .as_ref()
        .expect("download should succeed");
    assert!(
        content.len() > 100,
        "downloaded content should be non-trivial ({} bytes)",
        content.len()
    );

    // Parse
    let mut store = parser::DomainStore::new();
    let (exact_count, wildcard_count) = parser::parse_blocklist(content, "domains", 13, &mut store);
    assert!(
        exact_count > 0,
        "should have at least some exact domains, got {}",
        exact_count
    );
    eprintln!(
        "Domains format: {} exact, {} wildcard",
        exact_count, wildcard_count
    );

    // Compile
    let categories = vec![("appleTracker".to_string(), 13u8)];
    let data = binary::compile(&store, &categories);

    // Verify header
    let header = binary_reader::parse_header(&data).expect("header should parse");
    assert_eq!(header.magic, 0x5344424C);
    assert_eq!(header.version, 3);
    assert_eq!(header.exact_count, store.exact_domains.len() as u32);
    assert_eq!(header.wildcard_count, store.wildcard_suffixes.len() as u32);
    assert_eq!(header.total_size, data.len() as u64);

    // Spot-check: pick a few domains from the store and verify they're findable
    let sample_domains: Vec<String> = store.exact_domains.keys().take(5).cloned().collect();
    for domain in &sample_domains {
        let bitmap = binary_reader::lookup_exact(&data, &header, domain);
        assert!(
            bitmap.is_some(),
            "exact domain '{}' should be found in compiled binary",
            domain
        );
        assert!(
            (bitmap.unwrap() & (1 << 13)) != 0,
            "domain '{}' should have category 13 bit set",
            domain
        );
    }
}

/// Download a single adblock source → parse → compile → verify header + lookups.
///
/// Uses HaGeZi Anti-Piracy (adblock format, ~12k rules, category 11).
#[test]
#[ignore]
fn test_download_and_compile_adblock_format() {
    let cfg = single_source_config(
        "piracy",
        11,
        "anti.piracy.txt",
        "adblock",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock",
        "adblock",
    );

    // Download
    let results = downloader::download_all(&cfg);
    assert_eq!(results.len(), 1);
    let content = results[0]
        .content
        .as_ref()
        .expect("download should succeed");
    assert!(
        content.len() > 1000,
        "adblock list should be substantial ({} bytes)",
        content.len()
    );

    // Parse
    let mut store = parser::DomainStore::new();
    let (exact_count, wildcard_count) = parser::parse_blocklist(content, "adblock", 11, &mut store);
    assert!(
        exact_count > 100,
        "anti-piracy list should have many exact domains, got {}",
        exact_count
    );
    assert_eq!(
        wildcard_count, 0,
        "adblock format should not produce wildcards"
    );
    eprintln!(
        "Adblock format: {} exact, {} wildcard",
        exact_count, wildcard_count
    );

    // Compile
    let categories = vec![("piracy".to_string(), 11u8)];
    let data = binary::compile(&store, &categories);

    // Verify header
    let header = binary_reader::parse_header(&data).expect("header should parse");
    assert_eq!(header.magic, 0x5344424C);
    assert_eq!(header.version, 3);
    assert_eq!(header.exact_count, store.exact_domains.len() as u32);
    assert!(
        header.exact_count > 100,
        "compiled binary should contain many exact entries"
    );
    assert_eq!(header.total_size, data.len() as u64);

    // Spot-check: pick a few domains from the store and verify they're findable
    let sample_domains: Vec<String> = store.exact_domains.keys().take(5).cloned().collect();
    for domain in &sample_domains {
        let bitmap = binary_reader::lookup_exact(&data, &header, domain);
        assert!(
            bitmap.is_some(),
            "exact domain '{}' should be found in compiled binary",
            domain
        );
        assert!(
            (bitmap.unwrap() & (1 << 11)) != 0,
            "domain '{}' should have category 11 bit set",
            domain
        );
    }
}
