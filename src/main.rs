use dns_blocklist_compiler::counts;
use dns_blocklist_compiler::downloader::DownloadOutcome;
use dns_blocklist_compiler::run::{ReportInputs, RunStatus, build_validation_report};
use dns_blocklist_compiler::validator::{self, ValidationError};
use dns_blocklist_compiler::{binary, config, downloader, metadata, parser, reader};

use dns_blocklist_compiler::counts::{Baseline, SourceBaseline};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

struct CliArgs {
    output_dir: PathBuf,
    cache_dir: PathBuf,
}

fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut output_dir = PathBuf::from(".");
    let mut cache_dir = PathBuf::from("build/cache");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err("--output requires a directory argument".into());
                }
                output_dir = PathBuf::from(&args[i]);
            }
            "--cache" => {
                i += 1;
                if i >= args.len() {
                    return Err("--cache requires a directory argument".into());
                }
                cache_dir = PathBuf::from(&args[i]);
            }
            flag @ ("--strict" | "--best-effort") => {
                eprintln!(
                    "warning: {flag} is deprecated and ignored; severity is now fixed per guard."
                );
            }
            unknown => return Err(format!("unknown flag: {unknown}")),
        }
        i += 1;
    }
    Ok(CliArgs {
        output_dir,
        cache_dir,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cli = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {e}");
            eprintln!("Usage: dns-blocklist-compiler [--output <dir>] [--cache <dir>]");
            std::process::exit(2);
        }
    };
    let output_dir = cli.output_dir;
    let cache_dir = cli.cache_dir;

    let build_id = metadata::generate_build_id();

    println!("DNS Blocklist Compiler (SDBL V3)");
    println!("===============================================");
    println!("Build ID: {build_id}");
    println!("Output directory: {}", output_dir.display());
    println!("Cache directory: {}", cache_dir.display());
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

    // The previous run's baseline per source: its parsed count, and whether
    // a declared entry count was actually seen for it. A missing file reads
    // as empty, which raises nothing — a first run and an evicted cache
    // behave the same as a run whose counts all held steady.
    let baseline_path = cache_dir.join("source-counts.json");
    let previous_counts = counts::read(&baseline_path);
    println!(
        "Loaded {} baseline source count(s) from {}",
        previous_counts.len(),
        baseline_path.display()
    );
    println!();

    // Download all sources in parallel
    let results = downloader::download_all(&config);

    let mut store = parser::DomainStore::new();
    let mut total_downloaded = 0;
    let mut total_failed = 0;
    // Accumulated per-source lines for validation-report.txt (T7). Each line
    // corresponds to one configured source and captures download status,
    // parse delta, and the validate_parse verdict.
    let mut report_source_lines: Vec<String> = Vec::new();

    let mut parse_failures: Vec<ValidationError> = Vec::new();
    let mut degraded: Vec<ValidationError> = Vec::new();
    let mut current_counts: Baseline = Baseline::new();

    for result in &results {
        match &result.outcome {
            DownloadOutcome::Ok(content) => {
                let expected = parser::extract_expected_entry_count(content);
                // Lines-parsed counts feed only the validate_parse ratio guard;
                // categoryStats is computed from the compiled trie below.
                let (exact_lines, wildcard_lines) = parser::parse_blocklist(
                    content,
                    &result.source.format,
                    result.source.category_index,
                    &mut store,
                );
                let parsed_total = exact_lines + wildcard_lines;
                current_counts.insert(
                    result.source.display_name.clone(),
                    SourceBaseline {
                        parsed: parsed_total,
                        declared_count_seen: expected.is_some(),
                    },
                );
                // Degraded-only: this flags a source for a person to look at
                // without failing the run. `check_parse_degraded` runs both
                // guards and returns at most one error, so a source whose
                // parse falls and whose header vanishes in the same run is
                // reported once, not twice. `source_degraded` captures the
                // verdict here rather than having the report line re-scan
                // `degraded` by source name below.
                let mut source_degraded = false;
                if let Some(e) = validator::check_parse_degraded(
                    &result.source,
                    parsed_total,
                    expected,
                    previous_counts.get(&result.source.display_name),
                    config.build.max_parsed_drop_ratio,
                ) {
                    source_degraded = true;
                    degraded.push(e);
                }
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
                    None => format!("upstream: <none>, parsed: {parsed_total}"),
                };
                let verdict =
                    match validator::validate_parse(parsed_total, expected, &result.source) {
                        Ok(()) => {
                            if source_degraded {
                                "DEGRADED".to_string()
                            } else {
                                "OK".to_string()
                            }
                        }
                        Err(e) => {
                            let line = format!("FAIL ({e})");
                            parse_failures.push(e);
                            line
                        }
                    };
                let line = format!(
                    "  {} — {} — {}",
                    result.source.display_name, delta_str, verdict
                );
                println!("{line}");
                report_source_lines.push(line);
                total_downloaded += 1;
            }
            DownloadOutcome::Rejected(e) => {
                let line = format!(
                    "  {} — download REJECTED: {}",
                    result.source.display_name, e
                );
                println!("{line}");
                report_source_lines.push(line);
                total_failed += 1;
            }
            DownloadOutcome::NetworkError(msg) => {
                let line = format!("  {} — NETWORK ERROR: {}", result.source.display_name, msg);
                println!("{line}");
                report_source_lines.push(line);
                total_failed += 1;
            }
        }
    }

    println!();
    println!("Download Summary:");
    println!("  Successful: {total_downloaded}");
    println!("  Failed: {total_failed}");
    if !degraded.is_empty() {
        println!();
        println!("Degraded ({}):", degraded.len());
        for e in &degraded {
            println!("  - {e}");
            // A degraded run exits 0, so the Actions job shows the same green
            // check as a clean run; the only other record is inside
            // validation-report.txt. A workflow annotation surfaces it in the
            // Actions UI without changing the exit code. Harmless outside CI.
            eprintln!("::warning::{e}");
        }
    }
    let total_source_failures = total_failed + parse_failures.len();
    if total_source_failures > 0 {
        eprintln!(
            "ERROR: {} source(s) failed validation ({} download, {} parse). Aborting before compilation.",
            total_source_failures,
            total_failed,
            parse_failures.len()
        );
        for e in &parse_failures {
            eprintln!("  - {e}");
        }
        eprintln!("Status: {}", RunStatus::Failed.label());
        std::process::exit(RunStatus::Failed.exit_code());
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

    // Layer 3: round-trip + canary + per-bit floor against the just-compiled bytes.
    let canary_path = PathBuf::from("canary-domains.json");
    let canaries = match validator::load_canaries(&canary_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "ERROR: Failed to load canary-domains.json: {e}. Layer 3 cannot run without it."
            );
            eprintln!("Status: {}", RunStatus::Failed.label());
            std::process::exit(RunStatus::Failed.exit_code());
        }
    };
    println!();
    println!("Running output validation (Layer 3)...");
    let output_errors =
        validator::validate_output(&binary_data, &canaries, &config.sources, &store, 1000);
    let (hard_errors, floor_errors): (Vec<_>, Vec<_>) = output_errors.into_iter().partition(|e| {
        matches!(
            e,
            ValidationError::CanaryMissing { .. } | ValidationError::RoundTripMismatch { .. }
        )
    });
    // Canary + round-trip mismatches always abort: they indicate the artifact
    // itself is broken, not just under-supplied. Per-bit TrieEntriesBelowFloor
    // errors abort too — every guard keeps the severity that --strict gave it.
    if !hard_errors.is_empty() {
        eprintln!(
            "ERROR: {} canary/round-trip failure(s). Aborting before publishing.",
            hard_errors.len()
        );
        for e in &hard_errors {
            eprintln!("  - {e}");
        }
        eprintln!("Status: {}", RunStatus::Failed.label());
        std::process::exit(RunStatus::Failed.exit_code());
    }
    if !floor_errors.is_empty() {
        eprintln!(
            "ERROR: {} per-bit floor failure(s). Aborting before publishing.",
            floor_errors.len()
        );
        for e in &floor_errors {
            eprintln!("  - {e}");
        }
        eprintln!("Status: {}", RunStatus::Failed.label());
        std::process::exit(RunStatus::Failed.exit_code());
    }
    println!(
        "  OK — {} canary domain(s) round-tripped, sample lookups passed, per-bit floors met.",
        canaries.len()
    );

    // Rewrite the baseline from this run's counts. One fall therefore reports
    // exactly once, and the new count becomes the next run's normal.
    counts::write(&baseline_path, &current_counts);

    // categoryStats: count entries in the compiled trie tagged with each bit.
    // This replaces the previous "lines parsed per source" semantics with
    // "unique domains tagged with this category" — what consumers actually
    // want from blocklist.json's categoryStats.
    let header = reader::parse_header(&binary_data)
        .expect("validate_output just parsed the same bytes — header must parse");
    let exact_counts =
        reader::count_entries_per_bit(&binary_data, header.exact_trie_offset as usize);
    let wild_counts =
        reader::count_entries_per_bit(&binary_data, header.wildcard_trie_offset as usize);
    let category_stats: Vec<metadata::CategoryStat> = config
        .sources
        .iter()
        .map(|s| {
            let bit = s.category_index as usize;
            metadata::CategoryStat {
                name: s.category.clone(),
                exact: exact_counts[bit],
                wildcard: wild_counts[bit],
            }
        })
        .collect();

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

    // SHA-256. sha2 0.11 changed finalize() to return hybrid_array::Array<u8, ..>,
    // which no longer implements LowerHex — hex-encode byte-by-byte instead.
    let mut hasher = Sha256::new();
    hasher.update(&binary_data);
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write as _;
        write!(&mut sha256, "{byte:02x}").expect("writing to String never fails");
    }

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

    let status = if degraded.is_empty() {
        RunStatus::Ok
    } else {
        RunStatus::Degraded
    };

    // Validation report — uploaded as a workflow artifact alongside the binary.
    let report_path = output_dir.join("validation-report.txt");
    let report = build_validation_report(&ReportInputs {
        build_id: &build_id,
        status,
        total_sources: config.sources.len(),
        store: &store,
        source_lines: &report_source_lines,
        category_stats: &category_stats,
        canaries: &canaries,
        degraded: &degraded,
    });
    if let Err(e) = std::fs::write(&report_path, &report) {
        eprintln!("WARN: Failed to write validation-report.txt: {e}");
    } else {
        println!("Written validation report to {}", report_path.display());
    }

    println!();
    println!("SUCCESS: Pre-compiled blocklist generated");
    println!("  Binary: {}", binary_path.display());
    println!("  Metadata: {}", metadata_path.display());
    println!("  SHA256: {sha256}");
    println!("  Status: {}", status.label());
    std::process::exit(status.exit_code());
}
