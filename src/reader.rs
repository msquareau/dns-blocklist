//! SDBL v3 binary reader. Used at build time for round-trip validation
//! (canary lookups, sample re-checks, per-bit category counts). The
//! runtime reader in alpaca-doh-server is the canonical consumer; this
//! file mirrors enough of its parsing logic to spot a regression before
//! the artifact ships.

const MAGIC: u32 = 0x5344424C;
const VERSION: u32 = 3;
const HEADER_SIZE: usize = 48;

#[derive(Debug)]
pub struct SdblHeader {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub category_count: u32,
    pub exact_count: u32,
    pub wildcard_count: u32,
    pub exact_trie_offset: u64,
    pub wildcard_trie_offset: u64,
    pub total_size: u64,
}

#[derive(Debug)]
pub struct Category {
    pub index: u8,
    pub name: String,
}

pub fn parse_header(data: &[u8]) -> Result<SdblHeader, String> {
    if data.len() < HEADER_SIZE {
        return Err(format!(
            "Data too small for header: {} < {}",
            data.len(),
            HEADER_SIZE
        ));
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(format!("Bad magic: 0x{:08X} != 0x{:08X}", magic, MAGIC));
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(format!("Bad version: {} != {}", version, VERSION));
    }

    Ok(SdblHeader {
        magic,
        version,
        flags: u32::from_le_bytes(data[8..12].try_into().unwrap()),
        category_count: u32::from_le_bytes(data[12..16].try_into().unwrap()),
        exact_count: u32::from_le_bytes(data[16..20].try_into().unwrap()),
        wildcard_count: u32::from_le_bytes(data[20..24].try_into().unwrap()),
        exact_trie_offset: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        wildcard_trie_offset: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        total_size: u64::from_le_bytes(data[40..48].try_into().unwrap()),
    })
}

pub fn parse_categories(data: &[u8], header: &SdblHeader) -> Vec<Category> {
    let mut categories = Vec::new();
    let mut pos = HEADER_SIZE;

    for _ in 0..header.category_count {
        if pos >= data.len() {
            break;
        }
        let index = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;
        categories.push(Category { index, name });
    }

    categories
}

/// Walk the exact trie for a domain, returning the category bitmap if found.
pub fn lookup_exact(data: &[u8], header: &SdblHeader, domain: &str) -> Option<u32> {
    walk_trie(data, header.exact_trie_offset as usize, domain.as_bytes())
}

/// Walk the wildcard trie. Pass the suffix unreversed; this function reverses
/// it to match the on-disk storage order.
pub fn lookup_wildcard(data: &[u8], header: &SdblHeader, suffix: &str) -> Option<u32> {
    let reversed: String = suffix.chars().rev().collect();
    walk_trie(
        data,
        header.wildcard_trie_offset as usize,
        reversed.as_bytes(),
    )
}

fn walk_trie(data: &[u8], start_offset: usize, key: &[u8]) -> Option<u32> {
    let mut pos = start_offset;
    let mut key_idx = 0;

    loop {
        if pos >= data.len() {
            return None;
        }

        let flags = data[pos];
        let child_count = (flags >> 1) as usize;
        let is_terminal = (flags & 0x01) != 0;
        pos += 1;

        let bitmap = if is_terminal {
            let b = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            Some(b)
        } else {
            None
        };

        if key_idx >= key.len() {
            return bitmap;
        }

        let target = key[key_idx];
        let children_start = pos;
        let mut found = false;

        for i in 0..child_count {
            let entry_pos = children_start + i * 5;
            let child_byte = data[entry_pos];
            let offset_field_pos = entry_pos + 1;
            let relative_offset = u32::from_le_bytes(
                data[offset_field_pos..offset_field_pos + 4]
                    .try_into()
                    .unwrap(),
            );

            if child_byte == target {
                pos = offset_field_pos + relative_offset as usize;
                key_idx += 1;
                found = true;
                break;
            }
        }

        if !found {
            return None;
        }
    }
}

/// Walk every terminal node in the trie at `start_offset`. The callback
/// receives the key bytes (as accumulated during traversal) and the bitmap.
/// Iterative DFS to avoid stack depth on long domain keys.
pub fn walk_terminals<F: FnMut(&[u8], u32)>(data: &[u8], start_offset: usize, mut callback: F) {
    // Each stack frame: (node_offset, child_index, key_len_at_entry)
    let mut stack: Vec<(usize, usize, usize)> = vec![(start_offset, 0, 0)];
    let mut key: Vec<u8> = Vec::new();

    while let Some((node_pos, child_idx, key_len)) = stack.last().copied() {
        if node_pos >= data.len() {
            stack.pop();
            key.truncate(key_len);
            continue;
        }

        let flags = data[node_pos];
        let child_count = (flags >> 1) as usize;
        let is_terminal = (flags & 0x01) != 0;
        let bitmap_offset = node_pos + 1;
        let children_start = if is_terminal {
            bitmap_offset + 4
        } else {
            bitmap_offset
        };

        if child_idx == 0 && is_terminal {
            let bitmap =
                u32::from_le_bytes(data[bitmap_offset..bitmap_offset + 4].try_into().unwrap());
            callback(&key, bitmap);
        }

        if child_idx < child_count {
            let entry_pos = children_start + child_idx * 5;
            let child_byte = data[entry_pos];
            let offset_field_pos = entry_pos + 1;
            let relative_offset = u32::from_le_bytes(
                data[offset_field_pos..offset_field_pos + 4]
                    .try_into()
                    .unwrap(),
            );
            let next_pos = offset_field_pos + relative_offset as usize;

            // Bump current frame's child_idx, descend into child.
            // The child frame stores key.len() *before* the push so that
            // popping it restores key to the parent's depth.
            stack.last_mut().unwrap().1 += 1;
            let key_len_before_push = key.len();
            key.push(child_byte);
            stack.push((next_pos, 0, key_len_before_push));
        } else {
            // Exhausted children — pop and restore key to its length at this frame's entry.
            stack.pop();
            key.truncate(key_len);
        }
    }
}

/// Count how many terminal entries in `start_offset`'s trie have each of the
/// 32 category bits set.
pub fn count_entries_per_bit(data: &[u8], start_offset: usize) -> [usize; 32] {
    let mut counts = [0usize; 32];
    walk_terminals(data, start_offset, |_key, bitmap| {
        for (bit, slot) in counts.iter_mut().enumerate() {
            if bitmap & (1u32 << bit) != 0 {
                *slot += 1;
            }
        }
    });
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary;
    use crate::parser::DomainStore;

    fn build_small_store() -> DomainStore {
        let mut s = DomainStore::new();
        s.add_exact("doubleclick.net", 3);
        s.add_exact("doubleclick.net", 4);
        s.add_exact("www.doubleclick.net", 3);
        s.add_exact("www.doubleclick.net", 4);
        s.add_exact("phishing.example.com", 8);
        s.add_wildcard(".ads.example.com", 0);
        s
    }

    #[test]
    fn round_trips_exact_lookups() {
        let store = build_small_store();
        let cats = vec![
            ("adsTrackersProPlus".into(), 3u8),
            ("adsTrackersUltimate".into(), 4u8),
            ("malwarePhishing".into(), 8u8),
            ("adsTrackersLight".into(), 0u8),
        ];
        let data = binary::compile(&store, &cats);
        let header = parse_header(&data).unwrap();

        assert_eq!(
            lookup_exact(&data, &header, "doubleclick.net"),
            Some((1u32 << 3) | (1u32 << 4))
        );
        assert_eq!(
            lookup_exact(&data, &header, "phishing.example.com"),
            Some(1u32 << 8)
        );
        assert_eq!(lookup_exact(&data, &header, "not-in-list.com"), None);
    }

    #[test]
    fn round_trips_wildcard_lookups() {
        let store = build_small_store();
        let cats = vec![("adsTrackersLight".into(), 0u8)];
        let data = binary::compile(&store, &cats);
        let header = parse_header(&data).unwrap();

        assert_eq!(
            lookup_wildcard(&data, &header, ".ads.example.com"),
            Some(1u32 << 0)
        );
        assert_eq!(lookup_wildcard(&data, &header, ".missing.com"), None);
    }

    #[test]
    fn walk_terminals_visits_every_exact_entry_once() {
        let store = build_small_store();
        let cats = vec![("adsTrackersLight".into(), 0u8)];
        let data = binary::compile(&store, &cats);
        let header = parse_header(&data).unwrap();

        let mut found: Vec<(String, u32)> = Vec::new();
        walk_terminals(&data, header.exact_trie_offset as usize, |key, bitmap| {
            found.push((String::from_utf8_lossy(key).into_owned(), bitmap));
        });

        assert_eq!(found.len(), 3); // doubleclick.net, www.doubleclick.net, phishing.example.com
        let by_key: std::collections::BTreeMap<_, _> = found.into_iter().collect();
        assert_eq!(by_key["doubleclick.net"], (1u32 << 3) | (1u32 << 4));
        assert_eq!(by_key["phishing.example.com"], 1u32 << 8);
    }

    #[test]
    fn count_entries_per_bit_matches_store() {
        let store = build_small_store();
        let cats = vec![("adsTrackersLight".into(), 0u8)];
        let data = binary::compile(&store, &cats);
        let header = parse_header(&data).unwrap();

        let exact_counts = count_entries_per_bit(&data, header.exact_trie_offset as usize);
        assert_eq!(exact_counts[3], 2); // doubleclick.net, www.doubleclick.net
        assert_eq!(exact_counts[4], 2);
        assert_eq!(exact_counts[8], 1); // phishing.example.com
        assert_eq!(exact_counts[0], 0); // wildcard, not in exact trie

        let wild_counts = count_entries_per_bit(&data, header.wildcard_trie_offset as usize);
        assert_eq!(wild_counts[0], 1); // .ads.example.com
        assert_eq!(wild_counts[3], 0);
    }
}
