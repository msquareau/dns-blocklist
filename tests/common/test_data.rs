use dns_blocklist_compiler::parser::DomainStore;

/// Generate blocked domain names with a predictable pattern.
/// Returns `(domain, category_index)` pairs.
pub fn generate_blocked_domains(count: usize, category_index: u8) -> Vec<(String, u8)> {
    (0..count)
        .map(|i| {
            (
                format!("test-blocked-{:04}.cat{}.example.com", i, category_index),
                category_index,
            )
        })
        .collect()
}

/// Generate domain names that should NOT be in any blocklist.
pub fn generate_allowed_domains(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("allowed-{:04}.safe-domain.org", i))
        .collect()
}

/// Generate wildcard suffixes with a predictable pattern.
pub fn generate_wildcard_suffixes(count: usize, category_index: u8) -> Vec<(String, u8)> {
    (0..count)
        .map(|i| {
            (
                format!(".wild-{:04}.cat{}.example.com", i, category_index),
                category_index,
            )
        })
        .collect()
}

/// Build a DomainStore from exact and wildcard domain lists.
pub fn build_test_store(exact: &[(String, u8)], wildcards: &[(String, u8)]) -> DomainStore {
    let mut store = DomainStore::new();
    for (domain, cat_idx) in exact {
        store.add_exact(domain, *cat_idx);
    }
    for (suffix, cat_idx) in wildcards {
        store.add_wildcard(suffix, *cat_idx);
    }
    store
}
