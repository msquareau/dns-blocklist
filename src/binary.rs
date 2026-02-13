use crate::parser::DomainStore;
use crate::trie::Trie;
use std::collections::BTreeSet;

const MAGIC: u32 = 0x5344424C; // "SDBL"
const VERSION: u32 = 3;
const HEADER_SIZE: usize = 48;

pub fn compile(store: &DomainStore, categories: &[(String, u8)]) -> Vec<u8> {
    let estimated_size =
        HEADER_SIZE + (store.exact_domains.len() + store.wildcard_suffixes.len()) * 25;
    let mut data = Vec::with_capacity(estimated_size);

    // Build tries (BTreeMap gives sorted iteration → deterministic binary)
    let mut exact_trie = Trie::new();
    for (domain, &bitmap) in &store.exact_domains {
        exact_trie.insert(domain, bitmap);
    }

    let mut wildcard_trie = Trie::new();
    for (suffix, &bitmap) in &store.wildcard_suffixes {
        // Reverse using bytes — domain names are guaranteed ASCII
        let reversed: String =
            String::from_utf8(suffix.bytes().rev().collect()).expect("domain is ASCII");
        wildcard_trie.insert(&reversed, bitmap);
    }

    // Write header placeholder
    data.resize(HEADER_SIZE, 0);

    // Write deduplicated category table
    let mut seen = BTreeSet::new();
    let deduped_categories: Vec<_> = categories
        .iter()
        .filter(|(name, idx)| seen.insert((name.clone(), *idx)))
        .collect();

    for (name, index) in &deduped_categories {
        let name_bytes = name.as_bytes();
        assert!(
            name_bytes.len() <= 255,
            "category name '{}' is {} bytes, max is 255",
            name,
            name_bytes.len()
        );
        data.push(*index);
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);
    }

    // Record exact trie offset, serialize
    let exact_trie_offset = data.len() as u64;
    exact_trie.serialize(&mut data);

    // Record wildcard trie offset, serialize
    let wildcard_trie_offset = data.len() as u64;
    wildcard_trie.serialize(&mut data);

    // Build flags
    let mut flags: u32 = 0;
    if !store.exact_domains.is_empty() {
        flags |= 0x01;
    }
    if !store.wildcard_suffixes.is_empty() {
        flags |= 0x02;
    }

    // Patch header directly into data (no intermediate Vec)
    let total_size = data.len() as u64;
    let h = &mut data[..HEADER_SIZE];
    h[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    h[4..8].copy_from_slice(&VERSION.to_le_bytes());
    h[8..12].copy_from_slice(&flags.to_le_bytes());
    h[12..16].copy_from_slice(&(deduped_categories.len() as u32).to_le_bytes());
    h[16..20].copy_from_slice(&(store.exact_domains.len() as u32).to_le_bytes());
    h[20..24].copy_from_slice(&(store.wildcard_suffixes.len() as u32).to_le_bytes());
    h[24..32].copy_from_slice(&exact_trie_offset.to_le_bytes());
    h[32..40].copy_from_slice(&wildcard_trie_offset.to_le_bytes());
    h[40..48].copy_from_slice(&total_size.to_le_bytes());

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_header() {
        let mut store = DomainStore::new();
        store.add_exact("example.com", 0);
        store.add_wildcard(".wild.com", 1);

        let categories = vec![("cat0".to_string(), 0u8), ("cat1".to_string(), 1u8)];

        let data = compile(&store, &categories);

        // Check magic
        assert_eq!(&data[0..4], &MAGIC.to_le_bytes());
        // Check version
        assert_eq!(&data[4..8], &VERSION.to_le_bytes());
        // Check flags (both exact and wildcard present)
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 0x03);
        // Check category count
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 2);
        // Check exact count
        assert_eq!(u32::from_le_bytes(data[16..20].try_into().unwrap()), 1);
        // Check wildcard count
        assert_eq!(u32::from_le_bytes(data[20..24].try_into().unwrap()), 1);
        // Total size should equal data length
        assert_eq!(
            u64::from_le_bytes(data[40..48].try_into().unwrap()),
            data.len() as u64
        );
    }

    #[test]
    fn test_compile_starts_with_sdbl_magic() {
        let store = DomainStore::new();
        let data = compile(&store, &[]);
        assert_eq!(&data[0..4], &MAGIC.to_le_bytes());
    }

    #[test]
    fn test_compile_deduplicates_categories() {
        let mut store = DomainStore::new();
        store.add_exact("example.com", 0);

        // Same category appears twice (simulating multiple sources with same category)
        let categories = vec![
            ("ads".to_string(), 0u8),
            ("ads".to_string(), 0u8),
            ("trackers".to_string(), 1u8),
        ];

        let data = compile(&store, &categories);
        let cat_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(cat_count, 2, "duplicate categories should be deduplicated");
    }
}
