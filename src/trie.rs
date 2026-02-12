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
        serialize_node(&self.root, buf);
    }
}

fn serialize_node(node: &Node, buf: &mut Vec<u8>) {
    let child_count = node.children.len().min(127);
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

    // Recurse into each child; patch relative offset
    for (index, (_, child)) in node.children.iter().enumerate() {
        let child_node_offset = buf.len();
        let offset_placeholder_pos = child_entries_start + (index * 5) + 1;
        let relative_offset = (child_node_offset - offset_placeholder_pos) as u32;

        buf[offset_placeholder_pos..offset_placeholder_pos + 4]
            .copy_from_slice(&relative_offset.to_le_bytes());

        serialize_node(child, buf);
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
}
