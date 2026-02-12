use std::collections::HashMap;

pub struct DomainStore {
    pub exact_domains: HashMap<String, u32>,
    pub wildcard_suffixes: HashMap<String, u32>,
}

impl DomainStore {
    pub fn new() -> Self {
        Self {
            exact_domains: HashMap::new(),
            wildcard_suffixes: HashMap::new(),
        }
    }

    pub fn add_exact(&mut self, domain: &str, category_index: u8) {
        let bitmap: u32 = 1 << category_index;
        *self.exact_domains.entry(domain.to_string()).or_insert(0) |= bitmap;
    }

    pub fn add_wildcard(&mut self, suffix: &str, category_index: u8) {
        let bitmap: u32 = 1 << category_index;
        *self
            .wildcard_suffixes
            .entry(suffix.to_string())
            .or_insert(0) |= bitmap;
    }
}

pub fn parse_blocklist(
    content: &str,
    format: &str,
    category_index: u8,
    store: &mut DomainStore,
) -> (usize, usize) {
    let mut exact_count = 0;
    let mut wildcard_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let mut is_wildcard = false;

        let dom = match format {
            "hosts" => {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let ip = parts[0];
                if ip != "0.0.0.0" && ip != "127.0.0.1" {
                    continue;
                }
                parts[1].to_lowercase()
            }
            "domains" => {
                let mut d = trimmed.to_lowercase();
                if d.starts_with("*.") {
                    d = format!(".{}", &d[2..]);
                    is_wildcard = true;
                } else if d.starts_with('.') {
                    is_wildcard = true;
                }
                d
            }
            "adblock" => {
                let mut d = trimmed.to_string();
                if d.starts_with("||") {
                    d = d[2..].to_string();
                }
                if d.ends_with('^') {
                    d.pop();
                }
                if d.contains('$') || d.contains('/') || d.contains('*') {
                    continue;
                }
                d.to_lowercase()
            }
            _ => trimmed.to_lowercase(),
        };

        // Clean up: trim leading/trailing '.' and '*'
        let dom = dom.trim_matches(|c| c == '.' || c == '*').to_string();

        if dom.is_empty()
            || dom == "localhost"
            || dom == "localhost.localdomain"
            || dom == "local"
            || dom == "broadcasthost"
        {
            continue;
        }

        if !is_valid_domain(&dom) {
            continue;
        }

        if is_wildcard {
            store.add_wildcard(&format!(".{dom}"), category_index);
            wildcard_count += 1;
        } else {
            store.add_exact(&dom, category_index);
            exact_count += 1;
        }
    }

    (exact_count, wildcard_count)
}

fn is_valid_domain(domain: &str) -> bool {
    if !domain.contains('.') || domain.len() < 3 || domain.len() > 253 {
        return false;
    }

    // Check it's not an IPv4 address
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() == 4 {
        let all_numeric = parts.iter().all(|part| part.parse::<u8>().is_ok());
        if all_numeric {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domains_format() {
        let content = "example.com\n*.wild.com\n.suffix.com\n# comment\n\nlocalhost\n";
        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "domains", 0, &mut store);
        assert_eq!(exact, 1);
        assert_eq!(wildcard, 2);
        assert!(store.exact_domains.contains_key("example.com"));
        assert!(store.wildcard_suffixes.contains_key(".wild.com"));
        assert!(store.wildcard_suffixes.contains_key(".suffix.com"));
    }

    #[test]
    fn test_parse_hosts_format() {
        let content =
            "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.com\n192.168.1.1 skip.com\n";
        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "hosts", 1, &mut store);
        assert_eq!(exact, 2);
        assert_eq!(wildcard, 0);
        assert_eq!(store.exact_domains["ads.example.com"], 1 << 1);
        assert_eq!(store.exact_domains["tracker.example.com"], 1 << 1);
    }

    #[test]
    fn test_parse_adblock_format() {
        let content =
            "||example.com^\n||skip.com^$third-party\n||also.com/path\n! comment\n||valid.org^\n";
        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "adblock", 2, &mut store);
        assert_eq!(exact, 2);
        assert_eq!(wildcard, 0);
        assert!(store.exact_domains.contains_key("example.com"));
        assert!(store.exact_domains.contains_key("valid.org"));
    }

    #[test]
    fn test_skip_ip_addresses() {
        let content = "192.168.1.1\nexample.com\n";
        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(content, "domains", 0, &mut store);
        assert_eq!(exact, 1);
        assert!(!store.exact_domains.contains_key("192.168.1.1"));
    }

    #[test]
    fn test_category_bitmap_merging() {
        let mut store = DomainStore::new();
        store.add_exact("example.com", 0);
        store.add_exact("example.com", 3);
        assert_eq!(store.exact_domains["example.com"], (1 << 0) | (1 << 3));
    }

    #[test]
    fn test_skip_localhost_variants() {
        let content = "localhost\nlocalhost.localdomain\nlocal\nbroadcasthost\n";
        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "domains", 0, &mut store);
        assert_eq!(exact, 0);
        assert_eq!(wildcard, 0);
    }
}
