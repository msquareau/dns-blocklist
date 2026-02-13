# DNS Blocklist Compiler

Rust CLI tool that downloads DNS blocklists from popular open-source upstream sources and compiles them into a single categorized binary file (SDBL v3 format). Designed for DNS filtering apps, ad blockers, and network-level content filtering.

## Build Instructions

```bash
# Requirements: Rust 1.75+
git clone https://github.com/msquareau/dns-blocklist.git
cd dns-blocklist
cargo build --release
./target/release/dns-blocklist-compiler --output ./output
# Output: output/blocklist.bin, output/blocklist.bin.gz, output/blocklist.json
```

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

| Field | Description |
|-------|-------------|
| `category` | Unique category identifier (camelCase) |
| `categoryIndex` | Unique integer `0–255` — used as the bit position in the binary category bitmap |
| `file` | Filename appended to the base URL to form the download URL |
| `baseUrl` | Key into `baseUrls` — the download URL is `baseUrls[baseUrl]/file` |
| `format` | List format: `domains`, `hosts`, or `adblock` (see below) |
| `displayName` | Human-readable name shown in build output |

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

Copyright (C) 2026 M-SQAURE Pty Ltd, Australia

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

See [LICENSE.txt](LICENSE.txt) for the full license text.
