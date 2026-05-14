use crate::config::SourceEntry;
use crate::parser::{DomainStore, parse_blocklist};
use std::fmt;

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
        }
    }
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

/// Layer 2 entry. Currently enforces only the trivial parsed>=1 floor; full
/// ratio + min_parsed_entries semantics arrive in T3 (commit C3).
pub fn validate_parse(
    parsed: usize,
    _expected: Option<usize>,
    source: &SourceEntry,
) -> Result<(), ValidationError> {
    if parsed == 0 {
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
