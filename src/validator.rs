use crate::config::SourceEntry;
use crate::parser::{DomainStore, parse_blocklist};
use crate::reader;
use serde::Deserialize;
use std::fmt;
use std::path::Path;

const SMELL_TEST_LINES: usize = 30;
const ALLOWED_CONTENT_TYPES: &[&str] = &["text/plain", "text/"];
const REJECTED_CONTENT_TYPES: &[&str] = &["text/html", "application/json", "application/xml"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    HttpStatus {
        source: String,
        status: u16,
    },
    TooSmall {
        source: String,
        actual: usize,
        min: usize,
    },
    BadContentType {
        source: String,
        content_type: String,
    },
    NotADomainList {
        source: String,
        sampled: usize,
    },
    CountRegression {
        source: String,
        parsed: usize,
        expected: usize,
    },
    BelowFloor {
        source: String,
        parsed: usize,
        min: usize,
    },
    CanaryMissing {
        domain: String,
        want: u32,
        got: u32,
    },
    TrieEntriesBelowFloor {
        source: String,
        bit: u8,
        count: usize,
        min: usize,
    },
    AggregateFailures {
        count: usize,
        threshold: usize,
    },
    RoundTripMismatch {
        domain: String,
        expected: u32,
        got: u32,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpStatus { source, status } => {
                write!(f, "{source}: HTTP status {status} is not 2xx")
            }
            Self::TooSmall {
                source,
                actual,
                min,
            } => {
                write!(f, "{source}: body size {actual} below floor {min}")
            }
            Self::BadContentType {
                source,
                content_type,
            } => {
                write!(f, "{source}: rejected Content-Type {content_type:?}")
            }
            Self::NotADomainList { source, sampled } => {
                write!(
                    f,
                    "{source}: none of the first {sampled} non-comment lines parsed as a valid domain"
                )
            }
            Self::CountRegression {
                source,
                parsed,
                expected,
            } => {
                write!(
                    f,
                    "{source}: parsed {parsed} entries, upstream header declared {expected} (ratio {:.2}% below 90% floor)",
                    (*parsed as f64 / *expected as f64) * 100.0
                )
            }
            Self::BelowFloor {
                source,
                parsed,
                min,
            } => {
                write!(
                    f,
                    "{source}: parsed {parsed} below min_parsed_entries {min}"
                )
            }
            Self::CanaryMissing { domain, want, got } => {
                write!(
                    f,
                    "canary {domain}: expected bits {want:#010b} present, got {got:#010b}"
                )
            }
            Self::TrieEntriesBelowFloor {
                source,
                bit,
                count,
                min,
            } => {
                write!(
                    f,
                    "{source}: trie has {count} entries with bit {bit} set, below floor {min}"
                )
            }
            Self::AggregateFailures { count, threshold } => {
                write!(
                    f,
                    "{count} source(s) failed validation, exceeds threshold of {threshold}"
                )
            }
            Self::RoundTripMismatch {
                domain,
                expected,
                got,
            } => {
                write!(
                    f,
                    "round-trip mismatch for {domain}: store bitmap {expected:#x}, trie returned {got:#x}"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Canary {
    pub domain: String,
    pub expected_min_bitmap: u32,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Debug, Deserialize)]
pub struct CanaryFile {
    pub canaries: Vec<Canary>,
}

pub fn load_canaries(path: &Path) -> Result<Vec<Canary>, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let parsed: CanaryFile = serde_json::from_str(&data)?;
    Ok(parsed.canaries)
}

/// Run every Layer-3 check against the just-compiled SDBL v3 binary:
/// canary lookups, a sampled round-trip from `store`, and per-source
/// `min_trie_entries` floors. Returns every violation discovered so the
/// caller can decide whether to abort (strict) or warn (best-effort).
///
/// `sample_size` caps the number of exact + wildcard entries each
/// re-checked against the trie. Pick a value large enough to catch
/// systematic bugs but small enough to keep build time reasonable —
/// 1000 is the default the builder uses today.
pub fn validate_output(
    binary_data: &[u8],
    canaries: &[Canary],
    sources: &[SourceEntry],
    store: &DomainStore,
    sample_size: usize,
) -> Vec<ValidationError> {
    let mut errors: Vec<ValidationError> = Vec::new();

    let header = match reader::parse_header(binary_data) {
        Ok(h) => h,
        Err(e) => {
            errors.push(ValidationError::RoundTripMismatch {
                domain: format!("<header parse: {e}>"),
                expected: 0,
                got: 0,
            });
            return errors;
        }
    };

    for canary in canaries {
        let got = reader::lookup_exact(binary_data, &header, &canary.domain);
        if let Err(e) = validate_output_canary(&canary.domain, canary.expected_min_bitmap, got) {
            errors.push(e);
        }
    }

    // Sampled round-trip across both tries.
    let exact_stride = (store.exact_domains.len() / sample_size.max(1)).max(1);
    for (i, (domain, expected_bitmap)) in store.exact_domains.iter().enumerate() {
        if i % exact_stride != 0 {
            continue;
        }
        let got = reader::lookup_exact(binary_data, &header, domain);
        if got != Some(*expected_bitmap) {
            errors.push(ValidationError::RoundTripMismatch {
                domain: domain.clone(),
                expected: *expected_bitmap,
                got: got.unwrap_or(0),
            });
        }
    }
    let wild_stride = (store.wildcard_suffixes.len() / sample_size.max(1)).max(1);
    for (i, (suffix, expected_bitmap)) in store.wildcard_suffixes.iter().enumerate() {
        if i % wild_stride != 0 {
            continue;
        }
        let got = reader::lookup_wildcard(binary_data, &header, suffix);
        if got != Some(*expected_bitmap) {
            errors.push(ValidationError::RoundTripMismatch {
                domain: format!("wildcard {suffix}"),
                expected: *expected_bitmap,
                got: got.unwrap_or(0),
            });
        }
    }

    let exact_counts =
        reader::count_entries_per_bit(binary_data, header.exact_trie_offset as usize);
    let wild_counts =
        reader::count_entries_per_bit(binary_data, header.wildcard_trie_offset as usize);
    for source in sources {
        if let Some(min) = source.min_trie_entries {
            let bit = source.category_index as usize;
            let count = exact_counts[bit] + wild_counts[bit];
            if count < min {
                errors.push(ValidationError::TrieEntriesBelowFloor {
                    source: source.display_name.clone(),
                    bit: source.category_index,
                    count,
                    min,
                });
            }
        }
    }

    errors
}

impl std::error::Error for ValidationError {}

pub fn validate_download(
    status: u16,
    content_type: Option<&str>,
    body: &str,
    source: &SourceEntry,
) -> Result<(), ValidationError> {
    if !(200..=299).contains(&status) {
        return Err(ValidationError::HttpStatus {
            source: source.display_name.clone(),
            status,
        });
    }
    let min_size = source.min_size_bytes.unwrap_or(1);
    if body.len() < min_size {
        return Err(ValidationError::TooSmall {
            source: source.display_name.clone(),
            actual: body.len(),
            min: min_size,
        });
    }
    if let Some(ct) = content_type {
        let ct_lower = ct.to_ascii_lowercase();
        if REJECTED_CONTENT_TYPES
            .iter()
            .any(|bad| ct_lower.contains(bad))
        {
            return Err(ValidationError::BadContentType {
                source: source.display_name.clone(),
                content_type: ct.to_string(),
            });
        }
        if !ALLOWED_CONTENT_TYPES
            .iter()
            .any(|good| ct_lower.contains(good))
        {
            return Err(ValidationError::BadContentType {
                source: source.display_name.clone(),
                content_type: ct.to_string(),
            });
        }
    }
    if !looks_like_domain_list(body, &source.format) {
        return Err(ValidationError::NotADomainList {
            source: source.display_name.clone(),
            sampled: SMELL_TEST_LINES,
        });
    }
    Ok(())
}

fn looks_like_domain_list(body: &str, format: &str) -> bool {
    let sample: String = body
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with('!')
        })
        .take(SMELL_TEST_LINES)
        .collect::<Vec<_>>()
        .join("\n");
    if sample.is_empty() {
        return false;
    }
    let mut store = DomainStore::new();
    let (exact, wildcard) = parse_blocklist(&sample, format, 0, &mut store);
    exact + wildcard > 0
}

/// Validate the parser's output against (a) the upstream-declared entry count
/// (90 % floor) and (b) the source's optional `min_parsed_entries` floor.
/// The 90 % allowance lets the parser legitimately drop `localhost`, IPv4
/// addresses, malformed labels etc. while still catching the issue-#20 case
/// (657403 declared → 1 parsed).
pub fn validate_parse(
    parsed: usize,
    expected: Option<usize>,
    source: &SourceEntry,
) -> Result<(), ValidationError> {
    if let Some(exp) = expected
        && exp > 0
    {
        let floor = (exp as f64 * 0.90) as usize;
        if parsed < floor {
            return Err(ValidationError::CountRegression {
                source: source.display_name.clone(),
                parsed,
                expected: exp,
            });
        }
    }
    if let Some(min) = source.min_parsed_entries
        && parsed < min
    {
        return Err(ValidationError::BelowFloor {
            source: source.display_name.clone(),
            parsed,
            min,
        });
    }
    if expected.is_none() && source.min_parsed_entries.is_none() && parsed == 0 {
        return Err(ValidationError::BelowFloor {
            source: source.display_name.clone(),
            parsed,
            min: 1,
        });
    }
    Ok(())
}

pub fn validate_output_canary(
    domain: &str,
    expected_min_bitmap: u32,
    got: Option<u32>,
) -> Result<(), ValidationError> {
    let got = got.unwrap_or(0);
    if (got & expected_min_bitmap) != expected_min_bitmap {
        return Err(ValidationError::CanaryMissing {
            domain: domain.to_string(),
            want: expected_min_bitmap,
            got,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_source() -> SourceEntry {
        SourceEntry {
            category: "test".into(),
            category_index: 0,
            file: "test.txt".into(),
            base_url: "domains".into(),
            format: "domains".into(),
            display_name: "Test Source".into(),
            min_size_bytes: None,
            min_parsed_entries: None,
            min_trie_entries: None,
        }
    }

    #[test]
    fn rejects_non_2xx_status() {
        let src = fixture_source();
        let err = validate_download(404, Some("text/plain"), "anything", &src).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::HttpStatus { status: 404, .. }
        ));
    }

    #[test]
    fn rejects_empty_body() {
        let src = fixture_source();
        let err = validate_download(200, Some("text/plain"), "", &src).unwrap_err();
        assert!(matches!(err, ValidationError::TooSmall { actual: 0, .. }));
    }

    #[test]
    fn accepts_healthy_download() {
        let src = fixture_source();
        validate_download(200, Some("text/plain"), "example.com\n", &src).unwrap();
    }

    #[test]
    fn rejects_zero_parse_count() {
        let src = fixture_source();
        let err = validate_parse(0, None, &src).unwrap_err();
        assert!(matches!(err, ValidationError::BelowFloor { parsed: 0, .. }));
    }

    #[test]
    fn accepts_nonzero_parse_count() {
        let src = fixture_source();
        validate_parse(1, None, &src).unwrap();
        validate_parse(657403, Some(657403), &src).unwrap();
    }

    #[test]
    fn canary_missing_when_required_bits_absent() {
        let err = validate_output_canary("doubleclick.net", 0b11000, Some(0b01000)).unwrap_err();
        match err {
            ValidationError::CanaryMissing { domain, want, got } => {
                assert_eq!(domain, "doubleclick.net");
                assert_eq!(want, 0b11000);
                assert_eq!(got, 0b01000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn canary_missing_when_domain_not_in_trie() {
        let err = validate_output_canary("doubleclick.net", 0b11000, None).unwrap_err();
        assert!(matches!(err, ValidationError::CanaryMissing { got: 0, .. }));
    }

    #[test]
    fn canary_ok_when_all_required_bits_present() {
        validate_output_canary("doubleclick.net", 0b11000, Some(0b11000)).unwrap();
        validate_output_canary("doubleclick.net", 0b11000, Some(0b11111)).unwrap();
    }

    #[test]
    fn validation_error_display_formats() {
        let e = ValidationError::HttpStatus {
            source: "X".into(),
            status: 404,
        };
        assert!(e.to_string().contains("404"));

        let e = ValidationError::CountRegression {
            source: "Ultimate".into(),
            parsed: 1,
            expected: 657403,
        };
        let s = e.to_string();
        assert!(s.contains("657403"));
        assert!(s.contains("Ultimate"));
    }
}
