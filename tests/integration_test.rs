mod common;

use common::binary_reader;
use common::test_data;
use dns_blocklist_compiler::{binary, parser};

fn compile_test_binary(
    exact: &[(String, u8)],
    wildcards: &[(String, u8)],
    categories: &[(String, u8)],
) -> Vec<u8> {
    let store = test_data::build_test_store(exact, wildcards);
    binary::compile(&store, categories)
}

// ---------------------------------------------------------------------------
// 1. Header field validation
// ---------------------------------------------------------------------------
#[test]
fn test_header_all_fields() {
    let exact = test_data::generate_blocked_domains(5, 0);
    let wildcards = test_data::generate_wildcard_suffixes(3, 1);
    let categories = vec![("ads".to_string(), 0u8), ("trackers".to_string(), 1u8)];

    let data = compile_test_binary(&exact, &wildcards, &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    assert_eq!(header.magic, 0x5344424C, "magic should be SDBL");
    assert_eq!(header.version, 3, "version should be 3");
    assert_eq!(header.flags & 0x01, 0x01, "exact flag should be set");
    assert_eq!(header.flags & 0x02, 0x02, "wildcard flag should be set");
    assert_eq!(header.category_count, 2);
    assert_eq!(header.exact_count, 5);
    assert_eq!(header.wildcard_count, 3);
    assert!(
        header.exact_trie_offset > 48,
        "exact trie should be after header + categories"
    );
    assert!(
        header.wildcard_trie_offset > header.exact_trie_offset,
        "wildcard trie should be after exact trie"
    );
    assert_eq!(header.total_size, data.len() as u64);
}

// ---------------------------------------------------------------------------
// 2. Category table round-trip
// ---------------------------------------------------------------------------
#[test]
fn test_category_table_round_trip() {
    let categories = vec![
        ("ads".to_string(), 0u8),
        ("trackers".to_string(), 1u8),
        ("malware".to_string(), 2u8),
    ];
    let data = compile_test_binary(&[], &[], &categories);
    let header = binary_reader::parse_header(&data).unwrap();
    let cats = binary_reader::parse_categories(&data, &header);

    assert_eq!(cats.len(), 3);
    assert_eq!(cats[0].index, 0);
    assert_eq!(cats[0].name, "ads");
    assert_eq!(cats[1].index, 1);
    assert_eq!(cats[1].name, "trackers");
    assert_eq!(cats[2].index, 2);
    assert_eq!(cats[2].name, "malware");
}

// ---------------------------------------------------------------------------
// 3. 100 blocked domains found with correct bitmaps
// ---------------------------------------------------------------------------
#[test]
fn test_100_blocked_domains_found() {
    let ads = test_data::generate_blocked_domains(40, 0);
    let trackers = test_data::generate_blocked_domains(30, 1);
    let malware = test_data::generate_blocked_domains(30, 2);

    let all_exact: Vec<(String, u8)> = ads
        .iter()
        .chain(trackers.iter())
        .chain(malware.iter())
        .cloned()
        .collect();

    let categories = vec![
        ("ads".to_string(), 0u8),
        ("trackers".to_string(), 1u8),
        ("malware".to_string(), 2u8),
    ];

    let data = compile_test_binary(&all_exact, &[], &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    for (domain, cat_idx) in &all_exact {
        let bitmap = binary_reader::lookup_exact(&data, &header, domain);
        assert!(
            bitmap.is_some(),
            "domain '{}' (cat {}) not found in exact trie",
            domain,
            cat_idx
        );
        let bitmap = bitmap.unwrap();
        assert!(
            (bitmap & (1 << cat_idx)) != 0,
            "domain '{}' missing category bit {} in bitmap 0b{:032b}",
            domain,
            cat_idx,
            bitmap
        );
    }
}

// ---------------------------------------------------------------------------
// 4. 50 allowed domains absent
// ---------------------------------------------------------------------------
#[test]
fn test_50_allowed_domains_absent() {
    let blocked = test_data::generate_blocked_domains(20, 0);
    let categories = vec![("ads".to_string(), 0u8)];

    let data = compile_test_binary(&blocked, &[], &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    let allowed = test_data::generate_allowed_domains(50);
    for domain in &allowed {
        let result = binary_reader::lookup_exact(&data, &header, domain);
        assert!(
            result.is_none(),
            "allowed domain '{}' should NOT be in the trie, got bitmap {:?}",
            domain,
            result
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Category bitmap filtering
// ---------------------------------------------------------------------------
#[test]
fn test_category_bitmap_filtering() {
    let mut store = parser::DomainStore::new();
    store.add_exact("multi.example.com", 0);
    store.add_exact("multi.example.com", 1);

    let categories = vec![
        ("ads".to_string(), 0u8),
        ("trackers".to_string(), 1u8),
        ("malware".to_string(), 2u8),
    ];

    let data = binary::compile(&store, &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    let bitmap = binary_reader::lookup_exact(&data, &header, "multi.example.com").unwrap();
    assert!((bitmap & (1 << 0)) != 0, "should be in category 0 (ads)");
    assert!(
        (bitmap & (1 << 1)) != 0,
        "should be in category 1 (trackers)"
    );
    assert!(
        (bitmap & (1 << 2)) == 0,
        "should NOT be in category 2 (malware)"
    );
}

// ---------------------------------------------------------------------------
// 6. Multi-category bitmap merge
// ---------------------------------------------------------------------------
#[test]
fn test_multi_category_bitmap_merge() {
    let mut store = parser::DomainStore::new();
    store.add_exact("merged.example.com", 0);
    store.add_exact("merged.example.com", 3);
    store.add_exact("merged.example.com", 7);

    let categories = vec![("cat0".to_string(), 0u8)];
    let data = binary::compile(&store, &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    let bitmap = binary_reader::lookup_exact(&data, &header, "merged.example.com").unwrap();
    let expected = (1u32 << 0) | (1u32 << 3) | (1u32 << 7);
    assert_eq!(
        bitmap, expected,
        "bitmap should be (1<<0)|(1<<3)|(1<<7) = 0x{:X}, got 0x{:X}",
        expected, bitmap
    );
}

// ---------------------------------------------------------------------------
// 7. Wildcard trie reversed lookup
// ---------------------------------------------------------------------------
#[test]
fn test_wildcard_trie_reversed_lookup() {
    let wildcards = vec![(".ads.example.com".to_string(), 0u8)];
    let categories = vec![("ads".to_string(), 0u8)];

    let data = compile_test_binary(&[], &wildcards, &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    let bitmap = binary_reader::lookup_wildcard(&data, &header, ".ads.example.com");
    assert!(
        bitmap.is_some(),
        "wildcard suffix '.ads.example.com' should be found in wildcard trie"
    );
    assert!((bitmap.unwrap() & (1 << 0)) != 0);

    // A non-existent wildcard should return None
    let absent = binary_reader::lookup_wildcard(&data, &header, ".not.in.trie.com");
    assert!(absent.is_none());
}

// ---------------------------------------------------------------------------
// 8. Binary determinism
// ---------------------------------------------------------------------------
#[test]
fn test_binary_determinism() {
    let exact = test_data::generate_blocked_domains(50, 0);
    let wildcards = test_data::generate_wildcard_suffixes(10, 1);
    let categories = vec![("ads".to_string(), 0u8), ("trackers".to_string(), 1u8)];

    let data1 = compile_test_binary(&exact, &wildcards, &categories);
    let data2 = compile_test_binary(&exact, &wildcards, &categories);

    assert_eq!(
        data1.len(),
        data2.len(),
        "two compilations should produce same length"
    );
    assert_eq!(data1, data2, "two compilations should be byte-identical");
}

// ---------------------------------------------------------------------------
// 9. 10k domains stress test
// ---------------------------------------------------------------------------
#[test]
fn test_10k_domains_stress() {
    let exact = test_data::generate_blocked_domains(10_000, 0);
    let wildcards = test_data::generate_wildcard_suffixes(1_000, 1);
    let categories = vec![("ads".to_string(), 0u8), ("trackers".to_string(), 1u8)];

    let data = compile_test_binary(&exact, &wildcards, &categories);
    let header = binary_reader::parse_header(&data).unwrap();

    assert_eq!(header.exact_count, 10_000);
    assert_eq!(header.wildcard_count, 1_000);

    // Spot-check first, middle, and last exact domains
    for &i in &[0usize, 5000, 9999] {
        let (ref domain, cat_idx) = exact[i];
        let bitmap = binary_reader::lookup_exact(&data, &header, domain);
        assert!(
            bitmap.is_some(),
            "exact domain #{} '{}' not found",
            i,
            domain
        );
        assert!((bitmap.unwrap() & (1 << cat_idx)) != 0);
    }

    // Spot-check first, middle, and last wildcard suffixes
    for &i in &[0usize, 500, 999] {
        let (ref suffix, cat_idx) = wildcards[i];
        let bitmap = binary_reader::lookup_wildcard(&data, &header, suffix);
        assert!(
            bitmap.is_some(),
            "wildcard suffix #{} '{}' not found",
            i,
            suffix
        );
        assert!((bitmap.unwrap() & (1 << cat_idx)) != 0);
    }

    // Allowed domains should be absent
    let allowed = test_data::generate_allowed_domains(100);
    for domain in &allowed {
        assert!(binary_reader::lookup_exact(&data, &header, domain).is_none());
    }
}

// ---------------------------------------------------------------------------
// 10. Gzip round-trip
// ---------------------------------------------------------------------------
#[test]
fn test_gzip_round_trip() {
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Read, Write};

    let exact = test_data::generate_blocked_domains(100, 0);
    let categories = vec![("ads".to_string(), 0u8)];
    let original = compile_test_binary(&exact, &[], &categories);

    // Compress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();

    assert!(
        compressed.len() < original.len(),
        "compressed should be smaller than original"
    );

    // Decompress
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    assert_eq!(
        original, decompressed,
        "decompressed data should be byte-identical to original"
    );

    // Verify the decompressed data is still a valid SDBL binary
    let header = binary_reader::parse_header(&decompressed).unwrap();
    assert_eq!(header.exact_count, 100);
}
