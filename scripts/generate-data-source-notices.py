#!/usr/bin/env python3
"""Generate third-party notices for blocklist data sources.

Reads blocklist-sources.json and outputs a Markdown section attributing
each upstream provider with its license information.
"""

import json
import sys
from pathlib import Path

UNLICENSE_TEXT = """\
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>\
"""


def main():
    repo_root = Path(__file__).resolve().parent.parent
    config_path = repo_root / "blocklist-sources.json"

    with open(config_path) as f:
        config = json.load(f)

    hagezi = []
    blocklistproject = []

    for src in config["sources"]:
        if src["baseUrl"] == "blocklistproject":
            blocklistproject.append(src)
        else:
            hagezi.append(src)

    lines = []

    # --- HaGeZi ---
    if hagezi:
        lines.append("## HaGeZi DNS Blocklists")
        lines.append("")
        lines.append("- **Source:** <https://github.com/hagezi/dns-blocklists>")
        lines.append("- **License:** GPL-3.0-only")
        lines.append(f"- **Lists used:** {len(hagezi)}")
        lines.append("")
        lines.append("Categories included:")
        lines.append("")
        for src in sorted(hagezi, key=lambda s: s["categoryIndex"]):
            lines.append(f"- {src['displayName']} (`{src['category']}`)")
        lines.append("")
        lines.append("The full text of the GNU General Public License v3.0 is provided")
        lines.append("in [LICENSE.txt](LICENSE.txt) at the root of this repository and at")
        lines.append("<https://www.gnu.org/licenses/gpl-3.0.txt>.")
        lines.append("")

    # --- Block List Project ---
    if blocklistproject:
        lines.append("---")
        lines.append("")
        lines.append("## The Block List Project")
        lines.append("")
        lines.append("- **Source:** <https://github.com/blocklistproject/Lists>")
        lines.append("- **License:** Unlicense (Public Domain)")
        lines.append(f"- **Lists used:** {len(blocklistproject)}")
        lines.append("")
        lines.append("Categories included:")
        lines.append("")
        for src in sorted(blocklistproject, key=lambda s: s["categoryIndex"]):
            lines.append(f"- {src['displayName']} (`{src['category']}`)")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>License text</summary>")
        lines.append("")
        lines.append("```")
        lines.append(UNLICENSE_TEXT)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    sys.stdout.write("\n".join(lines))


if __name__ == "__main__":
    main()
