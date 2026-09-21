use crate::config::SourceEntry;
use crate::counts::SourceBaseline;
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
    ParsedDrop {
        source: String,
        parsed: usize,
        previous: usize,
    },
    CountNoLongerDeclared {
        source: String,
        previous: usize,
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
                write!(f, "{source}: parsed {parsed} below the minimum of {min}")
            }
            Self::ParsedDrop {
                source,
                parsed,
                previous,
            } => {
                let fell = (1.0 - (*parsed as f64 / *previous as f64)) * 100.0;
                write!(
                    f,
                    "{source}: parsed {parsed} lines, {fell:.1}% below the previous run's {previous}"
                )
            }
            Self::CountNoLongerDeclared { source, previous } => {
                write!(
                    f,
                    "{source}: upstream declared no entry count this run (previous baseline {previous}); the 90% guard is blind until it declares one again"
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
/// `min_trie_entries` floors. Returns every violation discovered; the caller
/// aborts before publishing on any of them — every Layer-3 guard is fatal,
/// so there is nothing here for the caller to grade by severity.
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

/// Validate the parser's output against the upstream-declared entry count
/// (90 % floor). The 90 % allowance lets the parser legitimately drop
/// `localhost`, IPv4 addresses, malformed labels etc. while still catching the
/// issue-#20 case (657403 declared → 1 parsed).
///
/// There is deliberately no absolute entry floor here. An upstream list that
/// trims itself is not a fault, and a hand-written floor turns that routine
/// event into a total publish outage. The shrink signal lives in
/// `check_parse_drop`, which is relative and never fatal.
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
    if parsed == 0 {
        return Err(ValidationError::BelowFloor {
            source: source.display_name.clone(),
            parsed,
            min: 1,
        });
    }
    Ok(())
}

/// Compare this run's parsed count with the previous run's.
///
/// This looks for partial corruption, not shrinkage. A source's count
/// ordinarily grows, with an occasional upstream cleanup that reduces it.
/// Neither is a fault, so `max_drop_ratio` sits far above a normal
/// consolidation. What it catches is the one shape the other guards miss: a
/// payload large enough to clear `min_size_bytes` that parses to a fraction of
/// what it did, while its category still clears `min_trie_entries`.
///
/// The caller records the result as degraded, never as a failure. The baseline
/// is rewritten from this run's counts, so one fall reports exactly once.
pub fn check_parse_drop(
    source: &SourceEntry,
    parsed: usize,
    previous: Option<usize>,
    max_drop_ratio: f64,
) -> Option<ValidationError> {
    let previous = previous.filter(|p| *p > 0)?;
    let fell = 1.0 - (parsed as f64 / previous as f64);
    if fell > max_drop_ratio {
        return Some(ValidationError::ParsedDrop {
            source: source.display_name.clone(),
            parsed,
            previous,
        });
    }
    None
}

/// Flag a source that declared a count last run but declares none this run.
///
/// Every source now depends on `extract_expected_entry_count` for its tight
/// 90% parse guard, and the absolute parse floor that used to back up the
/// six big lists is gone. If an upstream drops its header line,
/// `validate_parse` skips the ratio check entirely — nothing degrades and
/// nothing fails on its own. A source that quietly lost half its entries
/// would ship with no signal. This turns that silence into a degraded entry,
/// never a failure, so a person looks at it.
///
/// The condition is `declared_count_seen`, not the mere presence of a
/// baseline entry. A parsed-line count is recorded for every source that
/// downloads and parses, whether or not it ever carried a header, so a
/// source with no header by design has a baseline from its very first run
/// onward. Gating on the count alone would flag that source as degraded on
/// every run after the first, forever. Gating on `declared_count_seen`
/// instead means a source that never declared a count stays silent — there
/// is nothing for it to have lost.
pub fn check_missing_declared_count(
    source: &SourceEntry,
    expected: Option<usize>,
    previous: Option<&SourceBaseline>,
) -> Option<ValidationError> {
    if expected.is_some() {
        return None;
    }
    let previous = previous.filter(|b| b.declared_count_seen)?;
    Some(ValidationError::CountNoLongerDeclared {
        source: source.display_name.clone(),
        previous: previous.parsed,
    })
}

/// Run both parse-count degraded guards for one source and return at most
/// one error.
///
/// `check_parse_drop` takes priority. A source's parsed count can fall in
/// the same run that it stops declaring a count — the header line and the
/// body it introduces are often removed together — and reporting both
/// `ParsedDrop` and `CountNoLongerDeclared` would double-report one upstream
/// event as two degraded entries and two `::warning::` annotations.
/// `check_missing_declared_count` only runs when `check_parse_drop` found
/// nothing to report.
pub fn check_parse_degraded(
    source: &SourceEntry,
    parsed: usize,
    expected: Option<usize>,
    previous: Option<&SourceBaseline>,
    max_drop_ratio: f64,
) -> Option<ValidationError> {
    let previous_parsed = previous.map(|b| b.parsed);
    check_parse_drop(source, parsed, previous_parsed, max_drop_ratio)
        .or_else(|| check_missing_declared_count(source, expected, previous))
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
    fn parse_with_no_declared_count_and_no_entries_still_fails() {
        let src = fixture_source();
        let err = validate_parse(0, None, &src).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BelowFloor {
                parsed: 0,
                min: 1,
                ..
            }
        ));
    }

    #[test]
    fn a_shrunken_source_that_matches_its_header_passes() {
        // The 2026-09-21 HaGeZi Light case: upstream trimmed the list and the
        // parse matched the new header exactly. No floor may reject this.
        let src = fixture_source();
        validate_parse(65681, Some(65681), &src).unwrap();
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

    #[test]
    fn a_drop_past_the_ratio_is_reported() {
        let src = fixture_source();
        let err = check_parse_drop(&src, 30_000, Some(100_000), 0.6).unwrap();
        assert!(matches!(
            err,
            ValidationError::ParsedDrop {
                parsed: 30_000,
                previous: 100_000,
                ..
            }
        ));
    }

    #[test]
    fn the_hagezi_light_trim_is_not_reported() {
        // 2026-09-20 → 2026-09-21: 82665 → 65681, a fall of 20.5%.
        let src = fixture_source();
        assert!(check_parse_drop(&src, 65_681, Some(82_665), 0.6).is_none());
    }

    #[test]
    fn a_drop_exactly_at_the_ratio_is_not_reported() {
        let src = fixture_source();
        assert!(check_parse_drop(&src, 40_000, Some(100_000), 0.6).is_none());
    }

    #[test]
    fn growth_is_not_reported() {
        let src = fixture_source();
        assert!(check_parse_drop(&src, 200_000, Some(100_000), 0.6).is_none());
    }

    #[test]
    fn an_absent_baseline_is_not_reported() {
        let src = fixture_source();
        assert!(check_parse_drop(&src, 1, None, 0.6).is_none());
    }

    #[test]
    fn a_zero_baseline_is_not_reported() {
        let src = fixture_source();
        assert!(check_parse_drop(&src, 0, Some(0), 0.6).is_none());
    }

    fn declared_baseline(parsed: usize) -> SourceBaseline {
        SourceBaseline {
            parsed,
            declared_count_seen: true,
        }
    }

    fn undeclared_baseline(parsed: usize) -> SourceBaseline {
        SourceBaseline {
            parsed,
            declared_count_seen: false,
        }
    }

    #[test]
    fn a_source_that_stops_declaring_a_count_with_a_baseline_is_degraded() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        let err = check_missing_declared_count(&src, None, Some(&baseline)).unwrap();
        assert!(matches!(
            err,
            ValidationError::CountNoLongerDeclared {
                previous: 65_681,
                ..
            }
        ));
    }

    #[test]
    fn a_declared_count_is_never_flagged_as_missing() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        assert!(check_missing_declared_count(&src, Some(65_681), Some(&baseline)).is_none());
    }

    #[test]
    fn a_missing_count_with_no_baseline_is_not_flagged() {
        let src = fixture_source();
        assert!(check_missing_declared_count(&src, None, None).is_none());
    }

    // Properties 1 and 3: a source that has never declared a count stays
    // silent, on a first run with no baseline at all and on every run after
    // that records the same "no count seen" fact.

    #[test]
    fn property_3_a_first_run_with_no_baseline_stays_silent() {
        let src = fixture_source();
        assert!(check_missing_declared_count(&src, None, None).is_none());
    }

    #[test]
    fn property_1_a_source_that_never_declares_a_count_stays_silent_forever() {
        let src = fixture_source();
        // Run 1: no baseline yet, no count declared.
        assert!(check_missing_declared_count(&src, None, None).is_none());
        // Run 2: baseline now exists (main.rs records a parsed count for
        // every source), but declared_count_seen is false because run 1
        // never saw a header.
        let baseline = undeclared_baseline(12_345);
        assert!(check_missing_declared_count(&src, None, Some(&baseline)).is_none());
        // Run 3, 4, ...: the baseline keeps recording "no count seen" and
        // the guard keeps staying silent, however many runs pass.
        for _ in 0..5 {
            assert!(check_missing_declared_count(&src, None, Some(&baseline)).is_none());
        }
    }

    // Property 2: a source that declared a count last run and declares none
    // this run produces exactly one degraded entry.

    #[test]
    fn property_2_losing_a_previously_declared_count_is_reported_exactly_once() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        let errors: Vec<ValidationError> =
            [check_missing_declared_count(&src, None, Some(&baseline))]
                .into_iter()
                .flatten()
                .collect();
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0],
            ValidationError::CountNoLongerDeclared {
                previous: 65_681,
                ..
            }
        ));
    }

    #[test]
    fn count_no_longer_declared_display_names_the_source_and_baseline() {
        let e = ValidationError::CountNoLongerDeclared {
            source: "Test Source".into(),
            previous: 65_681,
        };
        let s = e.to_string();
        assert!(s.contains("Test Source"));
        assert!(s.contains("65681"));
    }

    #[test]
    fn parsed_drop_display_reports_the_percentage() {
        let e = ValidationError::ParsedDrop {
            source: "Test Source".into(),
            parsed: 30_000,
            previous: 100_000,
        };
        assert_eq!(
            e.to_string(),
            "Test Source: parsed 30000 lines, 70.0% below the previous run's 100000"
        );
    }

    // ============================================================
    // check_parse_degraded — the two guards must not double-report one
    // upstream event as two degraded entries.
    // ============================================================

    #[test]
    fn a_source_that_both_drops_and_loses_its_header_reports_only_the_drop() {
        let src = fixture_source();
        // Last run: parsed 100,000, and a count was declared.
        let baseline = declared_baseline(100_000);
        // This run: parsed only 30,000 (past the 0.6 drop ratio) and no
        // count is declared at all. Both check_parse_drop and
        // check_missing_declared_count would fire independently on this
        // input — check_parse_degraded must return only one error.
        let err = check_parse_degraded(&src, 30_000, None, Some(&baseline), 0.6).unwrap();
        assert!(
            matches!(err, ValidationError::ParsedDrop { .. }),
            "expected the drop to take priority, got {err:?}"
        );
    }

    #[test]
    fn check_parse_degraded_still_reports_a_lone_missing_count() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        // Parsed count held steady, so check_parse_drop has nothing to say;
        // check_missing_declared_count should still fire.
        let err = check_parse_degraded(&src, 65_681, None, Some(&baseline), 0.6).unwrap();
        assert!(matches!(err, ValidationError::CountNoLongerDeclared { .. }));
    }

    #[test]
    fn check_parse_degraded_still_reports_a_lone_drop() {
        let src = fixture_source();
        let baseline = declared_baseline(100_000);
        // A count is still declared this run, so check_missing_declared_count
        // has nothing to say; check_parse_drop should still fire.
        let err = check_parse_degraded(&src, 30_000, Some(30_000), Some(&baseline), 0.6).unwrap();
        assert!(matches!(err, ValidationError::ParsedDrop { .. }));
    }

    #[test]
    fn check_parse_degraded_is_silent_when_neither_guard_has_anything_to_say() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        assert!(check_parse_degraded(&src, 65_681, Some(65_681), Some(&baseline), 0.6).is_none());
    }

    // ============================================================
    // Property 5 — the missing-count guard is degraded-only. It must never
    // reach the failure count, the Failed status, or a non-zero exit.
    // ============================================================

    #[test]
    fn property_5_a_missing_declared_count_never_fails_validate_parse() {
        let src = fixture_source();
        // The same input that trips check_missing_declared_count into
        // degraded (no count declared, previous run declared one) must not
        // trip the fatal validate_parse guard, as long as some parse still
        // happened.
        let baseline = declared_baseline(65_681);
        assert!(check_missing_declared_count(&src, None, Some(&baseline)).is_some());
        validate_parse(65_681, None, &src).expect(
            "a source with no declared count this run must still pass validate_parse \
             on its own merits — the missing-count guard is degraded-only",
        );
    }

    #[test]
    fn property_5_a_missing_declared_count_degrades_the_run_status_not_the_exit_code() {
        let src = fixture_source();
        let baseline = declared_baseline(65_681);
        let mut degraded: Vec<ValidationError> = Vec::new();
        let mut parse_failures: Vec<ValidationError> = Vec::new();
        if let Some(e) = check_missing_declared_count(&src, None, Some(&baseline)) {
            degraded.push(e);
        }
        if let Err(e) = validate_parse(65_681, None, &src) {
            parse_failures.push(e);
        }
        assert_eq!(degraded.len(), 1);
        assert!(
            parse_failures.is_empty(),
            "a missing declared count must never land in the fatal parse-failure list"
        );
        // Mirrors main's status derivation: any failure means Failed with a
        // non-zero exit; the missing-count guard alone must never get there.
        let total_source_failures = parse_failures.len();
        assert_eq!(total_source_failures, 0);
    }
}
