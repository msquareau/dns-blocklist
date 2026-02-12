use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SourcesConfig {
    pub version: u32,
    pub description: String,
    pub base_urls: HashMap<String, String>,
    pub sources: Vec<SourceEntry>,
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
}
