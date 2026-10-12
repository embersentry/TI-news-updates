#!/usr/bin/env python3
"""Build ti-report.html by inlining ti-output-config.json into the viewer template.

Usage:  python3 build-report.py [config.json] [output.html]

The output path may sit in a directory that does not exist yet; it is created.
The daily workflow uses this to write a dated report per run, e.g.
reports/ti-report-2026-10-12.html.

The viewer also accepts drag-and-dropped JSON and, when served over http(s),
refreshes itself from a sibling ti-output-config.json - so rebuilding is only
needed to change the baked-in default dataset.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TEMPLATE = ROOT / "report-template.html"
PLACEHOLDER = "__TI_DATA__"


def main() -> int:
    cfg = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "ti-output-config.json"
    out = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "ti-report.html"

    for path in (TEMPLATE, cfg):
        if not path.is_file():
            print(f"error: missing {path}", file=sys.stderr)
            return 1

    data = json.loads(cfg.read_text(encoding="utf-8"))
    if "vulnerabilities" not in data:
        print(f"error: {cfg} has no 'vulnerabilities' key", file=sys.stderr)
        return 1

    # Escape '<' so the payload can never terminate the host <script> element.
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")

    template = TEMPLATE.read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        print(f"error: {TEMPLATE} has no {PLACEHOLDER} placeholder", file=sys.stderr)
        return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(template.replace(PLACEHOLDER, payload), encoding="utf-8")
    print(
        f"built {out.name}  "
        f"({len(data['vulnerabilities'])} entries, {out.stat().st_size / 1024:.0f} KB)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
