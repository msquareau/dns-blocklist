use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_build_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    base36_encode(timestamp)
}

fn base36_encode(mut value: u64) -> String {
    if value == 0 {
        return "0".to_string();
    }

    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::new();

    while value > 0 {
        result.push(ALPHABET[(value % 36) as usize]);
        value /= 36;
    }

    result.reverse();
    String::from_utf8(result).expect("base36 is always valid UTF-8")
}

pub fn generate_metadata(
    build_id: &str,
    binary_size: usize,
    sha256: &str,
    exact_count: usize,
    wildcard_count: usize,
    categories: &[String],
    category_stats: &[(String, usize, usize)],
) -> String {
    let now = chrono_like_now();
    let version = date_version();
    let filename = format!("blocklist-{build_id}.bin.gz");

    let categories_json: Vec<String> = categories.iter().map(|c| format!("\"{c}\"")).collect();

    let mut stats_entries = Vec::new();
    for (category, exact, wildcard) in category_stats {
        stats_entries.push(format!(
            "      \"{category}\": {{\"exact\": {exact}, \"wildcard\": {wildcard}}}"
        ));
    }
    let stats_json = format!("{{\n{}\n    }}", stats_entries.join(",\n"));

    format!(
        r#"{{
  "version": "{version}",
  "filename": "{filename}",
  "size": {binary_size},
  "sha256": "{sha256}",
  "domainCount": {domain_count},
  "exactCount": {exact_count},
  "wildcardCount": {wildcard_count},
  "categories": [{categories}],
  "categoryCount": {category_count},
  "published": "{now}",
  "minAppVersion": "1.0.0",
  "categoryStats": {stats_json}
}}"#,
        domain_count = exact_count + wildcard_count,
        categories = categories_json.join(", "),
        category_count = categories.len(),
    )
}

fn date_version() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();

    let (year, month, day) = unix_to_date(secs);
    format!("{year}.{month:02}.{day:02}")
}

fn chrono_like_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();

    let (year, month, day) = unix_to_date(secs);
    let day_secs = (secs % 86400) as u32;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    format!("{year}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn unix_to_date(timestamp: u64) -> (u64, u64, u64) {
    // Days since epoch
    let mut days = (timestamp / 86400) as i64;

    // Civil date from days (algorithm from Howard Hinnant)
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    (y as u64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base36_encode() {
        assert_eq!(base36_encode(0), "0");
        assert_eq!(base36_encode(35), "z");
        assert_eq!(base36_encode(36), "10");
        assert_eq!(base36_encode(1234567890), "kf12oi");
    }

    #[test]
    fn test_unix_to_date_epoch() {
        let (y, m, d) = unix_to_date(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_unix_to_date_known() {
        // 2024-01-15 00:00:00 UTC = 1705276800
        let (y, m, d) = unix_to_date(1705276800);
        assert_eq!((y, m, d), (2024, 1, 15));
    }

    #[test]
    fn test_generate_build_id_not_empty() {
        let id = generate_build_id();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_generate_metadata_structure() {
        let meta = generate_metadata(
            "test123",
            1000,
            "abc123",
            500,
            100,
            &["cat1".to_string(), "cat2".to_string()],
            &[("cat1".to_string(), 400, 50), ("cat2".to_string(), 100, 50)],
        );
        assert!(meta.contains("\"version\""));
        assert!(meta.contains("\"filename\": \"blocklist-test123.bin.gz\""));
        assert!(meta.contains("\"size\": 1000"));
        assert!(meta.contains("\"sha256\": \"abc123\""));
        assert!(meta.contains("\"domainCount\": 600"));
        assert!(meta.contains("\"exactCount\": 500"));
        assert!(meta.contains("\"wildcardCount\": 100"));
    }
}
