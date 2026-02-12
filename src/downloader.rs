use crate::config::{SourceEntry, SourcesConfig};
use rayon::prelude::*;
use std::io::Read;
use std::time::Duration;

pub struct DownloadResult {
    pub source: SourceEntry,
    pub content: Option<String>,
}

pub fn download_all(config: &SourcesConfig) -> Vec<DownloadResult> {
    let sources: Vec<_> = config.sources.clone();
    let total = sources.len();

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

            let content = match ureq::get(&url).timeout(Duration::from_secs(120)).call() {
                Ok(response) => {
                    let mut body = String::new();
                    match response.into_reader().read_to_string(&mut body) {
                        Ok(_) => {
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
