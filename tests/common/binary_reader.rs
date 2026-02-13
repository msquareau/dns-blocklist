/// SDBL v3 binary reader for integration tests.
/// Parses headers, category tables, and walks tries to verify domain lookups.

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

/// Walk the wildcard trie for a suffix. The caller should pass the suffix
/// (e.g. ".ads.example.com") already reversed, matching how the compiler stores it.
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

        // Read bitmap if terminal
        let bitmap = if is_terminal {
            let b = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            Some(b)
        } else {
            None
        };

        // If we've consumed all key bytes, check if this node is terminal
        if key_idx >= key.len() {
            return bitmap;
        }

        // Find the child matching the next key byte
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
                // Compute absolute offset: relative to the offset field position
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
