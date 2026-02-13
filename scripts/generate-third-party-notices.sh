#!/usr/bin/env bash
# Generate THIRD-PARTY-NOTICES.md combining Rust crate licenses and
# blocklist data-source attribution.
#
# Prerequisites: cargo-about (cargo install --locked cargo-about)
# Usage:         ./scripts/generate-third-party-notices.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="$REPO_ROOT/THIRD-PARTY-NOTICES.md"

if ! command -v cargo-about &>/dev/null; then
    echo "Error: cargo-about is not installed." >&2
    echo "Install with: cargo install --locked cargo-about" >&2
    exit 1
fi

echo "Generating THIRD-PARTY-NOTICES.md ..."

# --- Part I: Rust crate dependencies (via cargo-about) ---
echo "  [1/2] Generating Rust crate notices ..."
CRATES_MD=$(cd "$REPO_ROOT" && cargo about generate about.hbs 2>/dev/null)

# --- Part II: Blocklist data sources (via Python helper) ---
echo "  [2/2] Generating data-source notices ..."
DATA_MD=$(python3 "$SCRIPT_DIR/generate-data-source-notices.py")

# --- Combine ---
cat > "$OUTPUT" <<EOF
# Third-Party Notices

This file lists every third-party component used by the DNS Blocklist
Compiler, together with the applicable license terms.

The project itself is licensed under **GPL-3.0-only**
(see [LICENSE.txt](LICENSE.txt)).

---

# Part I — Rust Crate Dependencies

The compiler is built with the following open-source Rust crates.
Crates are grouped by the license under which they are used.

$CRATES_MD

---

# Part II — Blocklist Data Sources

The compiled blocklist binary incorporates domain data from the
following open-source projects.

$DATA_MD
EOF

echo "Done — wrote $OUTPUT ($(wc -l < "$OUTPUT") lines)."
