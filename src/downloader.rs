use crate::config::{SourceEntry, SourcesConfig};
use rayon::prelude::*;
use std::io::Read;
use std::time::Duration;
use ureq::Agent;

/// Maximum response body size (100 MB). Prevents OOM from malicious upstreams.
const MAX_RESPONSE_BYTES: u64 = 100 * 1024 * 1024;

pub struct DownloadResult {
    pub source: SourceEntry,
    pub content: Option<String>,
}

fn make_agent() -> Agent {
    Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into()
}

pub fn download_all(config: &SourcesConfig) -> Vec<DownloadResult> {
    let sources: Vec<_> = config.sources.clone();
    let total = sources.len();
    let agent = make_agent();

    sources
        .into_par_iter()
        .enumerate()
        .map(|(index, source)| {
            let base_url = match config.base_urls.get(&source.base_url) {
                Some(url) => url,
                None => {
                    eprintln!(
                        "[{}/{}] ERROR: Unknown baseUrl '{}' for {}",
                        index + 1,
                        total,
                        source.base_url,
                        source.category
                    );
                    return DownloadResult {
                        source,
                        content: None,
                    };
                }
            };

            let url = format!("{}/{}", base_url, source.file);
            eprintln!(
                "[{}/{}] Downloading {}...",
                index + 1,
                total,
                source.display_name
            );

            let content = match agent.get(&url).call() {
                Ok(mut response) => {
                    let mut bytes = Vec::new();
                    match response
                        .body_mut()
                        .as_reader()
                        .take(MAX_RESPONSE_BYTES)
                        .read_to_end(&mut bytes)
                    {
                        Ok(n) if n as u64 >= MAX_RESPONSE_BYTES => {
                            eprintln!(
                                "[{}/{}] ERROR: response for {} exceeded {} MB limit",
                                index + 1,
                                total,
                                source.display_name,
                                MAX_RESPONSE_BYTES / (1024 * 1024)
                            );
                            None
                        }
                        Ok(_) => {
                            let body = String::from_utf8_lossy(&bytes).into_owned();
                            eprintln!(
                                "[{}/{}] Downloaded {} ({} bytes)",
                                index + 1,
                                total,
                                source.display_name,
                                body.len()
                            );
                            Some(body)
                        }
                        Err(e) => {
                            eprintln!(
                                "[{}/{}] ERROR reading response for {}: {}",
                                index + 1,
                                total,
                                source.display_name,
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[{}/{}] ERROR downloading {}: {}",
                        index + 1,
                        total,
                        source.display_name,
                        e
                    );
                    None
                }
            };

            DownloadResult { source, content }
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
        }
    }

    #[test]
    fn test_download_result_with_content() {
        let source = make_source("ads", 0, "test.txt", "domains");
        let result = DownloadResult {
            source,
            content: Some("example.com\ntest.org\n".to_string()),
        };
        assert!(result.content.is_some());
        assert_eq!(result.source.category, "ads");
        assert_eq!(result.source.category_index, 0);
        let body = result.content.unwrap();
        assert!(body.contains("example.com"));
    }

    #[test]
    fn test_download_result_without_content() {
        let source = make_source("trackers", 1, "missing.txt", "domains");
        let result = DownloadResult {
            source,
            content: None,
        };
        assert!(result.content.is_none());
        assert_eq!(result.source.category, "trackers");
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
}
