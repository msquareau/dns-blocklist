use dns_blocklist_compiler::downloader::DownloadOutcome;
use dns_blocklist_compiler::validator::{self, ValidationError};
use dns_blocklist_compiler::{binary, config, downloader, metadata, parser};

/// Aggregate-failure threshold in strict mode. Wired to the CLI flag in C6 (T6).
const MAX_FAILED_SOURCES_STRICT: usize = 0;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() > 2 && args[1] == "--output" {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from(".")
    };

    let build_id = metadata::generate_build_id();

    println!("DNS Blocklist Compiler (SDBL V3)");
    println!("===============================================");
    println!("Build ID: {build_id}");
    println!("Output directory: {}", output_dir.display());
    println!();

    // Load config
    let config_path = PathBuf::from("blocklist-sources.json");
    let config = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Failed to load blocklist-sources.json: {e}");
            std::process::exit(1);
        }
    };

    println!("Loaded {} blocklist sources", config.sources.len());
    println!();

    // Download all sources in parallel
    let results = downloader::download_all(&config);

    let mut store = parser::DomainStore::new();
    let mut category_stats: Vec<metadata::CategoryStat> = Vec::new();
    let mut total_downloaded = 0;
    let mut total_failed = 0;

    let mut parse_failures: Vec<ValidationError> = Vec::new();

    for result in &results {
        match &result.outcome {
            DownloadOutcome::Ok(content) => {
                let expected = parser::extract_expected_entry_count(content);
                let (exact, wildcard) = parser::parse_blocklist(
                    content,
                    &result.source.format,
                    result.source.category_index,
                    &mut store,
                );
                let parsed_total = exact + wildcard;
                let delta_str = match expected {
                    Some(exp) => {
                        let delta = parsed_total as i64 - exp as i64;
                        let pct = if exp > 0 {
                            (parsed_total as f64 - exp as f64) / exp as f64 * 100.0
                        } else {
                            0.0
                        };
                        format!(
                            "upstream: {}, parsed: {} ({:+} / {:.1}%)",
                            exp, parsed_total, delta, pct
                        )
                    }
                    None => format!(
                        "upstream: <none>, parsed: {}{}",
                        parsed_total,
                        match result.source.min_parsed_entries {
                            Some(m) => format!(" (min_parsed_entries floor {})", m),
                            None => String::new(),
                        }
                    ),
                };
                match validator::validate_parse(parsed_total, expected, &result.source) {
                    Ok(()) => println!("  {} — {} — OK", result.source.display_name, delta_str),
                    Err(e) => {
                        println!(
                            "  {} — {} — FAIL ({})",
                            result.source.display_name, delta_str, e
                        );
                        parse_failures.push(e);
                    }
                }
                category_stats.push(metadata::CategoryStat {
                    name: result.source.category.clone(),
                    exact,
                    wildcard,
                });
                total_downloaded += 1;
            }
            DownloadOutcome::Rejected(_) | DownloadOutcome::NetworkError(_) => {
                total_failed += 1;
            }
        }
    }

    println!();
    println!("Download Summary:");
    println!("  Successful: {total_downloaded}");
    println!("  Failed: {total_failed}");
    if total_failed > MAX_FAILED_SOURCES_STRICT {
        eprintln!(
            "ERROR: {} source(s) failed download validation, strict-mode threshold is {}. Aborting before compilation.",
            total_failed, MAX_FAILED_SOURCES_STRICT
        );
        std::process::exit(1);
    }
    if !parse_failures.is_empty() {
        eprintln!(
            "ERROR: {} source(s) failed parse validation. Aborting before compilation.",
            parse_failures.len()
        );
        for e in &parse_failures {
            eprintln!("  - {e}");
        }
        std::process::exit(1);
    }
    println!();
    println!(
        "Total unique domains: {} exact, {} wildcard",
        store.exact_domains.len(),
        store.wildcard_suffixes.len()
    );

    // Compile to V3 binary
    println!();
    println!("Compiling to V3 trie format...");
    let start_time = Instant::now();

    let categories: Vec<(String, u8)> = config
        .sources
        .iter()
        .map(|s| (s.category.clone(), s.category_index))
        .collect();

    let binary_data = binary::compile(&store, &categories);
    let compile_time = start_time.elapsed();
    println!("Compilation time: {:.2}s", compile_time.as_secs_f64());

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        eprintln!("ERROR: Failed to create output directory: {e}");
        std::process::exit(1);
    }

    // Write binary
    let binary_path = output_dir.join("blocklist.bin");
    if let Err(e) = std::fs::write(&binary_path, &binary_data) {
        eprintln!("ERROR: Failed to write blocklist.bin: {e}");
        std::process::exit(1);
    }
    println!("Written {} bytes to blocklist.bin", binary_data.len());

    // SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&binary_data);
    let sha256 = format!("{:x}", hasher.finalize());

    // Gzip compress
    let gz_path = output_dir.join("blocklist.bin.gz");
    let gz_file = match std::fs::File::create(&gz_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ERROR: Failed to create blocklist.bin.gz: {e}");
            std::process::exit(1);
        }
    };
    let mut encoder = GzEncoder::new(gz_file, Compression::best());
    if let Err(e) = encoder.write_all(&binary_data) {
        eprintln!("ERROR: Failed to write gzip data: {e}");
        std::process::exit(1);
    }
    if let Err(e) = encoder.finish() {
        eprintln!("ERROR: Failed to finish gzip: {e}");
        std::process::exit(1);
    }
    println!("Written compressed blocklist.bin.gz");

    // Metadata (reuse categories vec for category names)
    let category_names: Vec<String> = categories.iter().map(|(name, _)| name.clone()).collect();
    let metadata_json = metadata::generate_metadata(
        &build_id,
        binary_data.len(),
        &sha256,
        store.exact_domains.len(),
        store.wildcard_suffixes.len(),
        &category_names,
        &category_stats,
    );

    let metadata_path = output_dir.join("blocklist.json");
    if let Err(e) = std::fs::write(&metadata_path, &metadata_json) {
        eprintln!("ERROR: Failed to write blocklist.json: {e}");
        std::process::exit(1);
    }
    println!("Written metadata to blocklist.json");

    println!();
    println!("SUCCESS: Pre-compiled blocklist generated");
    println!("  Binary: {}", binary_path.display());
    println!("  Metadata: {}", metadata_path.display());
    println!("  SHA256: {sha256}");
}
