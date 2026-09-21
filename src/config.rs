use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Build-wide validation settings. The block is optional, so a config written
/// before it existed still loads.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BuildSettings {
    /// The fraction a source's parsed count may fall against the previous run
    /// before the run records a degraded entry. It sits far above a normal
    /// upstream consolidation on purpose.
    #[serde(default = "default_max_parsed_drop_ratio")]
    pub max_parsed_drop_ratio: f64,
}

fn default_max_parsed_drop_ratio() -> f64 {
    0.6
}

impl Default for BuildSettings {
    fn default() -> Self {
        Self {
            max_parsed_drop_ratio: default_max_parsed_drop_ratio(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SourcesConfig {
    pub version: u32,
    pub description: String,
    pub base_urls: HashMap<String, String>,
    pub sources: Vec<SourceEntry>,
    #[serde(default)]
    pub build: BuildSettings,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SourceEntry {
    pub category: String,
    pub category_index: u8,
    pub file: String,
    pub base_url: String,
    pub format: String,
    pub display_name: String,
    #[serde(default)]
    pub min_size_bytes: Option<usize>,
    #[serde(default)]
    pub min_trie_entries: Option<usize>,
}

pub fn load_config(path: &Path) -> Result<SourcesConfig, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let config: SourcesConfig = serde_json::from_str(&data)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "version": 1,
            "description": "Test",
            "baseUrls": {"domains": "https://example.com"},
            "sources": [{
                "category": "test",
                "categoryIndex": 0,
                "file": "test.txt",
                "baseUrl": "domains",
                "format": "domains",
                "displayName": "Test List"
            }]
        }"#;
        let config: SourcesConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.sources[0].category, "test");
        assert_eq!(config.sources[0].category_index, 0);
        assert_eq!(config.base_urls["domains"], "https://example.com");
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config(Path::new("/nonexistent/path/blocklist-sources.json"));
        assert!(result.is_err());
    }

    #[test]
    fn build_settings_default_to_a_zero_point_six_drop_ratio() {
        let json = r#"{
            "version": 1,
            "description": "No build block",
            "baseUrls": {},
            "sources": []
        }"#;
        let config: SourcesConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.build.max_parsed_drop_ratio, 0.6);
    }

    #[test]
    fn build_settings_read_an_explicit_drop_ratio() {
        let json = r#"{
            "version": 1,
            "description": "Explicit build block",
            "baseUrls": {},
            "sources": [],
            "build": {"maxParsedDropRatio": 0.25}
        }"#;
        let config: SourcesConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.build.max_parsed_drop_ratio, 0.25);
    }

    #[test]
    fn test_deserialize_multiple_sources() {
        let json = r#"{
            "version": 1,
            "description": "Multi-source test",
            "baseUrls": {
                "domains": "https://example.com/domains",
                "adblock": "https://example.com/adblock"
            },
            "sources": [
                {
                    "category": "ads",
                    "categoryIndex": 0,
                    "file": "ads.txt",
                    "baseUrl": "domains",
                    "format": "domains",
                    "displayName": "Ads List"
                },
                {
                    "category": "trackers",
                    "categoryIndex": 1,
                    "file": "trackers.txt",
                    "baseUrl": "domains",
                    "format": "domains",
                    "displayName": "Tracker List"
                },
                {
                    "category": "malware",
                    "categoryIndex": 2,
                    "file": "malware.txt",
                    "baseUrl": "adblock",
                    "format": "adblock",
                    "displayName": "Malware List"
                }
            ]
        }"#;
        let config: SourcesConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sources.len(), 3);
        assert_eq!(config.base_urls.len(), 2);
        assert_eq!(config.sources[0].category, "ads");
        assert_eq!(config.sources[1].format, "domains");
        assert_eq!(config.sources[2].base_url, "adblock");
        assert_eq!(config.sources[2].format, "adblock");
    }

    #[test]
    fn test_deserialize_empty_sources() {
        let json = r#"{
            "version": 1,
            "description": "Empty",
            "baseUrls": {},
            "sources": []
        }"#;
        let config: SourcesConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sources.len(), 0);
        assert_eq!(config.base_urls.len(), 0);
    }
}
