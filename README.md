# DNS Blocklist Compiler

Rust CLI tool that downloads DNS blocklists from popular open-source upstream sources and compiles them into a single categorized binary file (SDBL v3 format). Designed for DNS filtering apps, ad blockers, and network-level content filtering.

## Build Instructions

```bash
# Requirements: Rust 1.85+
git clone https://github.com/msquareau/dns-blocklist.git
cd dns-blocklist
cargo build --release
./target/release/dns-blocklist-compiler --output ./output
# Output: output/blocklist.bin, output/blocklist.bin.gz, output/blocklist.json
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--output <dir>` | `.` | Where to write `blocklist.bin`, `blocklist.bin.gz`, and `blocklist.json`. |
| `--strict` | (default) | Abort on any validation failure: bad download, parse-count regression, canary mismatch, per-bit floor breach. CI should use strict. |
| `--best-effort` | | Tolerate up to 2 source-level (download or parse) failures and per-bit floor breaches — they downgrade to `WARN` lines. Canary mismatches and round-trip mismatches still abort because they indicate the artifact is broken, not just under-supplied. Use for local development iterations. |

### Validation layers

The compiler runs three validation passes; any of them can stop a bad artifact from shipping:

1. **Layer 1 — download.** HTTP status must be 2xx, body must meet the source's optional `minSizeBytes`, `Content-Type` must be `text/*` (not `text/html` / `application/json`), and the first 30 non-comment lines must contain at least one parseable domain. Retries: 3× with 1s/2s/4s ±20 % jitter for network errors and 5xx.
2. **Layer 2 — parse.** If the source emits a HaGeZi-style `# Number of entries: N` header, parsed count must be ≥ 90 % of N. Independently, the source's optional `minParsedEntries` floor must be met.
3. **Layer 3 — output.** The just-compiled binary is parsed back through `src/reader.rs`, every canary in [`canary-domains.json`](canary-domains.json) is looked up and its `expectedMinBitmap` bits must be present, ~1000 random store entries are round-tripped through the trie, and every source's optional `minTrieEntries` floor is checked against the trie's per-bit terminal counts.

## Testing

```bash
cargo test                        # Run all 33 tests (unit + integration)
cargo clippy -- -D warnings       # Lint check
cargo fmt --check                 # Format check
```

The test suite includes:

- **23 unit tests** — parser formats, trie serialization, header encoding, metadata generation, config deserialization
- **10 integration tests** — end-to-end compilation with a binary reader that walks the serialized SDBL v3 tries to verify domain lookups, category bitmaps, wildcard handling, determinism, and gzip round-trips

## How It Works

1. Downloads DNS blocklists in parallel from upstream open-source sources
2. Parses three list formats: plain domains, hosts files, and adblock rules
3. Builds a trie data structure with category bitmaps
4. Serializes to SDBL v3 binary format for fast domain lookup
5. Generates metadata JSON with SHA-256 checksums and domain statistics

## Configuring Blocklist Sources

All blocklist sources are defined in [`blocklist-sources.json`](blocklist-sources.json). You can add, remove, or modify sources by editing this file.

### File Structure

```json
{
  "version": 1,
  "description": "Human-readable description of this config",
  "baseUrls": {
    "domains": "https://example.com/domains",
    "adblock": "https://example.com/adblock"
  },
  "sources": [
    {
      "category": "adsTrackers",
      "categoryIndex": 0,
      "file": "ads.txt",
      "baseUrl": "domains",
      "format": "domains",
      "displayName": "Ad Trackers List"
    }
  ]
}
```

### Fields

**Top-level:**

| Field | Description |
|-------|-------------|
| `version` | Config schema version (currently `1`) |
| `description` | Human-readable description |
| `baseUrls` | Named URL prefixes referenced by sources |
| `sources` | Array of blocklist source entries |

**Each source entry:**

| Field | Required | Description |
|-------|----------|-------------|
| `category` | yes | Unique category identifier (camelCase) |
| `categoryIndex` | yes | Unique integer `0–31` — used as the bit position in the binary category bitmap |
| `file` | yes | Filename appended to the base URL to form the download URL |
| `baseUrl` | yes | Key into `baseUrls` — the download URL is `baseUrls[baseUrl]/file` |
| `format` | yes | List format: `domains`, `hosts`, or `adblock` (see below) |
| `displayName` | yes | Human-readable name shown in build output |
| `minSizeBytes` | optional | Layer 1 — reject downloads smaller than this many bytes. Set ~80 % of the current upstream size. |
| `minParsedEntries` | optional | Layer 2 — reject parses producing fewer than this many entries (line count). Independent of the upstream's declared count. |
| `minTrieEntries` | optional | Layer 3 — abort if the compiled trie has fewer than this many entries with this source's bit set. |

### Supported Formats

| Format | Description | Example line |
|--------|-------------|--------------|
| `domains` | Plain domain list, one per line. Supports `*.` and `.` wildcard prefixes. | `example.com` |
| `hosts` | Hosts file format (`0.0.0.0` or `127.0.0.1` followed by a domain). | `0.0.0.0 example.com` |
| `adblock` | Adblock filter syntax. Only `\|\|domain^` rules are used; rules with `$`, `/`, or `*` are skipped. | `\|\|example.com^` |

### Adding a New Source

1. If the source uses a new base URL, add it to `baseUrls`.
2. Add a new entry to `sources` with a unique `category` and `categoryIndex`.
3. Run the compiler to verify the source downloads and parses correctly:
   ```bash
   cargo run -- --output ./output
   ```

## Third-Party Sources and Licensing

This tool aggregates domain lists from the following open-source projects. The compiled binary output incorporates data from these sources and is subject to the terms of their respective licenses.

| Source | License | Notes |
|--------|---------|-------|
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | GPL-3.0-only | 28 category lists |
| [The Block List Project](https://github.com/blocklistproject/Lists) | Unlicense | 1 category list |

A complete list of upstream sources with URLs is maintained in [`blocklist-sources.json`](blocklist-sources.json).

Because the majority of upstream data is licensed under the GNU General Public License v3.0, the compiled output and this tool are also distributed under GPL-3.0. If you redistribute the compiled blocklist binary, you must comply with the GPL-3.0 terms — including making the corresponding source code (this repository) available to recipients.

For a complete list of all third-party software and data sources, including full license texts, see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Copyright (C) 2026 M-SQUARE Pty Ltd, Australia

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

See [LICENSE.txt](LICENSE.txt) for the full license text.
