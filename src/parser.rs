use std::collections::BTreeMap;

pub struct DomainStore {
    pub exact_domains: BTreeMap<String, u32>,
    pub wildcard_suffixes: BTreeMap<String, u32>,
}

impl Default for DomainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainStore {
    pub fn new() -> Self {
        Self {
            exact_domains: BTreeMap::new(),
            wildcard_suffixes: BTreeMap::new(),
        }
    }

    pub fn add_exact(&mut self, domain: &str, category_index: u8) {
        assert!(
            category_index < 32,
            "category_index must be < 32, got {category_index}"
        );
        let bitmap: u32 = 1u32 << category_index;
        *self.exact_domains.entry(domain.to_string()).or_insert(0) |= bitmap;
    }

    pub fn add_wildcard(&mut self, suffix: &str, category_index: u8) {
        assert!(
            category_index < 32,
            "category_index must be < 32, got {category_index}"
        );
        let bitmap: u32 = 1u32 << category_index;
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

        let dom: String = match format {
            "hosts" => {
                let mut parts = trimmed.split_whitespace();
                let ip = match parts.next() {
                    Some(ip) => ip,
                    None => continue,
                };
                if ip != "0.0.0.0" && ip != "127.0.0.1" {
                    continue;
                }
                let domain = match parts.next() {
                    Some(d) => d,
                    None => continue,
                };
                // Strip inline comment glued to domain (e.g. "tracker.com#comment")
                let domain = domain.split('#').next().unwrap_or(domain);
                domain.to_lowercase()
            }
            "domains" => {
                let s = trimmed;
                let s = if let Some(rest) = s.strip_prefix("*.") {
                    is_wildcard = true;
                    rest
                } else if let Some(rest) = s.strip_prefix('.') {
                    is_wildcard = true;
                    rest
                } else {
                    s
                };
                s.to_lowercase()
            }
            "adblock" => {
                let s = trimmed;
                let s = s.strip_prefix("||").unwrap_or(s);
                let s = s.strip_suffix('^').unwrap_or(s);
                if s.contains('$') || s.contains('/') || s.contains('*') {
                    continue;
                }
                s.to_lowercase()
            }
            _ => trimmed.to_lowercase(),
        };

        // Clean up: trim leading/trailing '.' and '*'
        let dom = dom.trim_matches(|c: char| c == '.' || c == '*');

        if dom.is_empty()
            || dom == "localhost"
            || dom == "localhost.localdomain"
            || dom == "local"
            || dom == "broadcasthost"
        {
            continue;
        }

        if !is_valid_domain(dom) {
            continue;
        }

        if is_wildcard {
            let mut suffix = String::with_capacity(dom.len() + 1);
            suffix.push('.');
            suffix.push_str(dom);
            store.add_wildcard(&suffix, category_index);
            wildcard_count += 1;
        } else {
            store.add_exact(dom, category_index);
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

    // Reject domains with invalid characters
    for label in &parts {
        if label.is_empty() {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
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

    #[test]
    fn test_parse_case_insensitive() {
        let content = "EXAMPLE.COM\nexample.com\nExample.Com\n";
        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(content, "domains", 0, &mut store);
        // All three lines should merge into one entry (lowercased)
        assert_eq!(exact, 3); // parse counts lines processed, not unique
        assert_eq!(store.exact_domains.len(), 1);
        assert!(store.exact_domains.contains_key("example.com"));
    }

    #[test]
    fn test_parse_empty_and_comment_only() {
        let content = "";
        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "domains", 0, &mut store);
        assert_eq!(exact, 0);
        assert_eq!(wildcard, 0);

        let comment_only = "# this is a comment\n! also a comment\n   \n";
        let (exact2, wildcard2) = parse_blocklist(comment_only, "domains", 0, &mut store);
        assert_eq!(exact2, 0);
        assert_eq!(wildcard2, 0);
        assert!(store.exact_domains.is_empty());
    }

    #[test]
    fn test_parse_domain_too_long() {
        // 254 chars total (over the 253 limit)
        let long_label = "a".repeat(245);
        let long_domain = format!("{}.example.com", long_label);
        assert!(long_domain.len() > 253);

        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(&long_domain, "domains", 0, &mut store);
        assert_eq!(exact, 0, "domain over 253 chars should be rejected");
        assert!(store.exact_domains.is_empty());
    }

    #[test]
    fn test_hosts_format_with_comments_and_tabs() {
        let content = "\
0.0.0.0\tads.example.com\n\
127.0.0.1\ttracker.example.com\t# inline comment\n\
0.0.0.0 tabbed.example.com # another comment\n\
::1 ipv6only.example.com\n\
# full line comment\n\
0.0.0.0 valid.example.org\n";

        let mut store = DomainStore::new();
        let (exact, wildcard) = parse_blocklist(content, "hosts", 5, &mut store);

        // Tab-separated lines should parse, ::1 should be skipped
        assert_eq!(wildcard, 0);
        assert!(store.exact_domains.contains_key("ads.example.com"));
        assert!(store.exact_domains.contains_key("tracker.example.com"));
        assert!(store.exact_domains.contains_key("tabbed.example.com"));
        assert!(store.exact_domains.contains_key("valid.example.org"));
        // ::1 is neither 0.0.0.0 nor 127.0.0.1, so it should be skipped
        assert!(!store.exact_domains.contains_key("ipv6only.example.com"));
        // The inline-comment tokens should not be treated as domains
        assert!(!store.exact_domains.contains_key("#"));
        assert_eq!(exact, 4);
    }

    #[test]
    fn test_hosts_format_inline_comment_glued() {
        let content = "0.0.0.0 tracker.example.com#comment\n";
        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(content, "hosts", 0, &mut store);
        assert_eq!(exact, 1);
        assert!(store.exact_domains.contains_key("tracker.example.com"));
        assert!(
            !store
                .exact_domains
                .contains_key("tracker.example.com#comment")
        );
    }

    #[test]
    fn test_adblock_skip_complex_rules() {
        let content = "||valid.example.com^\n||has-dollar.com^$third-party\n||has-slash.com/path\n||has-star.com*wild\n||also-valid.org^\n";
        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(content, "adblock", 0, &mut store);
        assert_eq!(exact, 2);
        assert!(store.exact_domains.contains_key("valid.example.com"));
        assert!(store.exact_domains.contains_key("also-valid.org"));
        assert!(!store.exact_domains.contains_key("has-dollar.com"));
        assert!(!store.exact_domains.contains_key("has-slash.com"));
        assert!(!store.exact_domains.contains_key("has-star.com"));
    }

    #[test]
    #[should_panic(expected = "category_index must be < 32")]
    fn test_category_index_overflow_panics() {
        let mut store = DomainStore::new();
        store.add_exact("example.com", 32);
    }

    #[test]
    fn test_reject_domains_with_invalid_chars() {
        let content =
            "valid.example.com\ninvalid@domain.com\nbad[bracket.com\nok-hyphen.example.org\n";
        let mut store = DomainStore::new();
        let (exact, _) = parse_blocklist(content, "domains", 0, &mut store);
        assert_eq!(exact, 2);
        assert!(store.exact_domains.contains_key("valid.example.com"));
        assert!(store.exact_domains.contains_key("ok-hyphen.example.org"));
        assert!(!store.exact_domains.contains_key("invalid@domain.com"));
        assert!(!store.exact_domains.contains_key("bad[bracket.com"));
    }
}
