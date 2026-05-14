use crate::config::{SourceEntry, SourcesConfig};
use crate::validator::{ValidationError, validate_download};
use rayon::prelude::*;
use std::io::Read;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::Agent;
use ureq::http::header::CONTENT_TYPE;

/// Maximum response body size (100 MB). Prevents OOM from malicious upstreams.
const MAX_RESPONSE_BYTES: u64 = 100 * 1024 * 1024;

/// Retry attempts on transient (network / 5xx) failures.
const RETRY_ATTEMPTS: u32 = 3;

#[derive(Debug)]
pub enum DownloadOutcome {
    Ok(String),
    Rejected(ValidationError),
    NetworkError(String),
}

impl DownloadOutcome {
    pub fn content(&self) -> Option<&str> {
        match self {
            Self::Ok(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

pub struct DownloadResult {
    pub source: SourceEntry,
    pub outcome: DownloadOutcome,
}

fn make_agent() -> Agent {
    Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Compute backoff in milliseconds for `attempt` (0-indexed). Base 1s, 2s, 4s with ±20 % jitter.
/// `jitter_bps` is in basis points (0..10000) — 10000 means "+20 %", 0 means "-20 %".
fn compute_backoff_ms(attempt: u32, jitter_bps: u32) -> u64 {
    let base_ms: u64 = 1000u64 << attempt;
    let range_ms = (base_ms * 4) / 10; // 40 % total span
    let offset_ms = (jitter_bps as u64).min(10_000) * range_ms / 10_000;
    base_ms.saturating_sub(range_ms / 2) + offset_ms
}

fn random_jitter_bps() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % 10_000
}

fn attempt_download(agent: &Agent, url: &str) -> Result<(u16, Option<String>, String), String> {
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| format!("request failed: {e}"))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut bytes = Vec::new();
    let n = response
        .body_mut()
        .as_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("body read failed: {e}"))?;
    if n as u64 >= MAX_RESPONSE_BYTES {
        return Err(format!(
            "response exceeded {} MB cap",
            MAX_RESPONSE_BYTES / (1024 * 1024)
        ));
    }
    let body = String::from_utf8_lossy(&bytes).into_owned();
    Ok((status, content_type, body))
}

fn download_one(agent: &Agent, url: &str, source: &SourceEntry) -> DownloadOutcome {
    let mut last_network_err: Option<String> = None;
    let mut last_5xx: Option<u16> = None;

    for attempt in 0..RETRY_ATTEMPTS {
        match attempt_download(agent, url) {
            Err(net_err) => {
                last_network_err = Some(net_err);
            }
            Ok((status, content_type, body)) => {
                if (500..=599).contains(&status) {
                    last_5xx = Some(status);
                } else {
                    return match validate_download(status, content_type.as_deref(), &body, source) {
                        Ok(()) => DownloadOutcome::Ok(body),
                        Err(e) => DownloadOutcome::Rejected(e),
                    };
                }
            }
        }
        if attempt + 1 < RETRY_ATTEMPTS {
            let backoff = compute_backoff_ms(attempt, random_jitter_bps());
            thread::sleep(Duration::from_millis(backoff));
        }
    }

    if let Some(status) = last_5xx {
        DownloadOutcome::Rejected(ValidationError::HttpStatus {
            source: source.display_name.clone(),
            status,
        })
    } else {
        DownloadOutcome::NetworkError(
            last_network_err.unwrap_or_else(|| "unknown network failure".into()),
        )
    }
}

pub fn download_all(config: &SourcesConfig) -> Vec<DownloadResult> {
    let sources: Vec<_> = config.sources.clone();
    let total = sources.len();
    let agent = make_agent();

    sources
        .into_par_iter()
        .enumerate()
        .map(|(index, source)| {
            let prefix = format!("[{}/{}]", index + 1, total);
            let base_url = match config.base_urls.get(&source.base_url) {
                Some(url) => url,
                None => {
                    let reason = format!("unknown baseUrl '{}'", source.base_url);
                    eprintln!("{} ERROR: {} for {}", prefix, reason, source.display_name);
                    return DownloadResult {
                        source,
                        outcome: DownloadOutcome::NetworkError(reason),
                    };
                }
            };
            let url = format!("{}/{}", base_url, source.file);
            eprintln!("{} Downloading {}...", prefix, source.display_name);

            let outcome = download_one(&agent, &url, &source);
            match &outcome {
                DownloadOutcome::Ok(body) => eprintln!(
                    "{} Downloaded {} ({} bytes)",
                    prefix,
                    source.display_name,
                    body.len()
                ),
                DownloadOutcome::Rejected(e) => {
                    eprintln!("{} REJECTED {}: {}", prefix, source.display_name, e)
                }
                DownloadOutcome::NetworkError(msg) => {
                    eprintln!("{} NETWORK ERROR {}: {}", prefix, source.display_name, msg)
                }
            }
            DownloadResult { source, outcome }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_source(category: &str, cat_idx: u8, file: &str, base_url: &str) -> SourceEntry {
        SourceEntry {
            category: category.to_string(),
            category_index: cat_idx,
            file: file.to_string(),
            base_url: base_url.to_string(),
            format: "domains".to_string(),
            display_name: format!("Test {}", category),
            min_size_bytes: None,
            min_parsed_entries: None,
            min_trie_entries: None,
        }
    }

    #[test]
    fn test_download_outcome_ok() {
        let outcome = DownloadOutcome::Ok("example.com\n".into());
        assert!(outcome.is_ok());
        assert_eq!(outcome.content(), Some("example.com\n"));
    }

    #[test]
    fn test_download_outcome_rejected_has_no_content() {
        let outcome = DownloadOutcome::Rejected(ValidationError::HttpStatus {
            source: "X".into(),
            status: 404,
        });
        assert!(!outcome.is_ok());
        assert_eq!(outcome.content(), None);
    }

    #[test]
    fn test_download_result_with_content() {
        let source = make_source("ads", 0, "test.txt", "domains");
        let result = DownloadResult {
            source,
            outcome: DownloadOutcome::Ok("example.com\ntest.org\n".to_string()),
        };
        assert!(result.outcome.is_ok());
        assert_eq!(result.source.category, "ads");
        assert_eq!(result.source.category_index, 0);
        let body = result.outcome.content().unwrap();
        assert!(body.contains("example.com"));
    }

    #[test]
    fn test_download_result_without_content() {
        let source = make_source("trackers", 1, "missing.txt", "domains");
        let result = DownloadResult {
            source,
            outcome: DownloadOutcome::NetworkError("dns failure".into()),
        };
        assert!(!result.outcome.is_ok());
        assert_eq!(result.source.file, "missing.txt");
    }

    #[test]
    fn test_url_resolution() {
        let mut base_urls = HashMap::new();
        base_urls.insert(
            "domains".to_string(),
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains".to_string(),
        );
        let source = make_source("ads", 0, "light.txt", "domains");

        let base_url = base_urls.get(&source.base_url).unwrap();
        let url = format!("{}/{}", base_url, source.file);
        assert_eq!(
            url,
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/light.txt"
        );
    }

    #[test]
    fn compute_backoff_ms_min_is_negative_20_percent() {
        // attempt 0, jitter 0bps → 1000ms - 20% = 800ms
        assert_eq!(compute_backoff_ms(0, 0), 800);
    }

    #[test]
    fn compute_backoff_ms_max_is_positive_20_percent() {
        // attempt 0, jitter 10000bps → 1000ms + 20% = 1200ms
        assert_eq!(compute_backoff_ms(0, 10_000), 1200);
    }

    #[test]
    fn compute_backoff_ms_doubles_per_attempt() {
        // mid-jitter (5000bps) → base
        assert_eq!(compute_backoff_ms(0, 5_000), 1000);
        assert_eq!(compute_backoff_ms(1, 5_000), 2000);
        assert_eq!(compute_backoff_ms(2, 5_000), 4000);
    }
}
