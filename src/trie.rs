use std::collections::BTreeMap;

pub struct Node {
    pub children: BTreeMap<u8, Box<Node>>,
    pub is_terminal: bool,
    pub category_bitmap: u32,
}

impl Node {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            is_terminal: false,
            category_bitmap: 0,
        }
    }
}

pub struct Trie {
    pub root: Node,
    pub count: usize,
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

impl Trie {
    pub fn new() -> Self {
        Self {
            root: Node::new(),
            count: 0,
        }
    }

    pub fn insert(&mut self, key: &str, bitmap: u32) {
        let mut node = &mut self.root;

        for byte in key.bytes() {
            node = node
                .children
                .entry(byte)
                .or_insert_with(|| Box::new(Node::new()));
        }

        if !node.is_terminal {
            self.count += 1;
        }
        node.is_terminal = true;
        node.category_bitmap |= bitmap;
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        // Reserve estimated capacity: ~20 bytes per entry (flags + bitmap + child entries)
        buf.reserve(self.count * 20);
        serialize_iterative(&self.root, buf);
    }
}

/// Iterative DFS serialization using an explicit stack.
/// Produces the same byte-for-byte output as the recursive version
/// without risk of stack overflow on deep tries.
fn serialize_iterative(root: &Node, buf: &mut Vec<u8>) {
    enum Work<'a> {
        Serialize(&'a Node),
        PatchOffset(usize), // buf position of the 4-byte relative offset to patch
    }

    let mut stack = vec![Work::Serialize(root)];

    while let Some(work) = stack.pop() {
        match work {
            Work::PatchOffset(offset_pos) => {
                let relative_offset = (buf.len() - offset_pos) as u32;
                buf[offset_pos..offset_pos + 4].copy_from_slice(&relative_offset.to_le_bytes());
            }
            Work::Serialize(node) => {
                let child_count = node.children.len();
                assert!(
                    child_count <= 127,
                    "trie node has {child_count} children, max is 127"
                );

                let mut flags = (child_count as u8) << 1;
                if node.is_terminal {
                    flags |= 0x01;
                }
                buf.push(flags);

                if node.is_terminal {
                    buf.extend_from_slice(&node.category_bitmap.to_le_bytes());
                }

                // Write child entries: 1 byte char + 4 bytes placeholder offset
                let child_entries_start = buf.len();
                for &byte in node.children.keys() {
                    buf.push(byte);
                    buf.extend_from_slice(&[0, 0, 0, 0]); // placeholder
                }

                // Push children in reverse order so the first child is processed first (LIFO)
                for (index, (_, child)) in node.children.iter().enumerate().rev() {
                    let offset_pos = child_entries_start + (index * 5) + 1;
                    stack.push(Work::Serialize(child));
                    stack.push(Work::PatchOffset(offset_pos));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_count() {
        let mut trie = Trie::new();
        trie.insert("abc", 1);
        trie.insert("abd", 2);
        trie.insert("abc", 4); // re-insert, should not increment count
        assert_eq!(trie.count, 2);
        // bitmap should be OR'd
        let mut node = &trie.root;
        for b in "abc".bytes() {
            node = &node.children[&b];
        }
        assert!(node.is_terminal);
        assert_eq!(node.category_bitmap, 1 | 4);
    }

    #[test]
    fn test_serialize_single_entry() {
        let mut trie = Trie::new();
        trie.insert("a", 0x01);
        let mut buf = Vec::new();
        trie.serialize(&mut buf);

        // Root: flags = (1 child << 1) | 0 = 0x02
        assert_eq!(buf[0], 0x02);
        // Child byte = 'a'
        assert_eq!(buf[1], b'a');
        // After placeholder (4 bytes), child node at offset 6
        // Child node: flags = (0 children << 1) | 1 = 0x01
        assert_eq!(buf[6], 0x01);
        // Bitmap: 0x01000000 in LE = [0x01, 0x00, 0x00, 0x00]
        assert_eq!(&buf[7..11], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_empty_trie() {
        let trie = Trie::new();
        let mut buf = Vec::new();
        trie.serialize(&mut buf);
        // Root: no children, not terminal -> flags = 0x00
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_shared_prefix_count() {
        let mut trie = Trie::new();
        trie.insert("example.com", 1);
        trie.insert("example.org", 2);
        trie.insert("example.net", 4);
        assert_eq!(trie.count, 3);

        // All three should be terminal with their respective bitmaps
        let mut node = &trie.root;
        for b in "example.".bytes() {
            node = &node.children[&b];
        }
        // After "example." we should have 3 children: 'c', 'n', 'o'
        assert_eq!(node.children.len(), 3);
        assert!(!node.is_terminal);
    }

    #[test]
    fn test_single_char_keys() {
        let mut trie = Trie::new();
        trie.insert("a", 0x01);
        trie.insert("b", 0x02);
        trie.insert("c", 0x04);

        assert_eq!(trie.count, 3);

        let mut buf = Vec::new();
        trie.serialize(&mut buf);

        // Root should have 3 children, not terminal
        assert_eq!(buf[0] >> 1, 3); // child_count = 3
        assert_eq!(buf[0] & 0x01, 0); // not terminal

        // After flags byte, 3 child entries: [byte, u32_offset] × 3 = 15 bytes
        // Then 3 child nodes, each terminal with 1 byte flags + 4 bytes bitmap
        // Total: 1 + 15 + 3*(1+4) = 31 bytes
        assert_eq!(buf.len(), 31);
    }
}
