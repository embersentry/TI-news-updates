#!/usr/bin/env python3
"""Build a TI report by inlining ti-output-config.json into the viewer template.

Usage:  python3 build-report.py [config.json] [output.html]

Two payloads are injected:

  __TI_DATA__   the config being rendered - drives the vulnerability listing
  __TI_INDEX__  an index of every report in reports/ - drives the timeline

The index is derived by scanning reports/*.html and reading the ti-data block
each one already embeds, so it is always a true reflection of what is on disk
and needs no separate state file to keep in step. When the output path is itself
a dated report that does not exist yet, its entry is added from the config being
rendered, so a report always appears in its own timeline.

The output path may sit in a directory that does not exist yet; it is created.
The daily workflow uses this to write a dated report per run, e.g.
reports/ti-report-2026-10-12.html.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TEMPLATE = ROOT / "report-template.html"
REPORTS_DIR = ROOT / "reports"
DATA_PLACEHOLDER = "__TI_DATA__"
INDEX_PLACEHOLDER = "__TI_INDEX__"

DATED_NAME = re.compile(r"^ti-report-(\d{4}-\d{2}-\d{2})\.html$")
EMBEDDED = re.compile(
    r'<script id="ti-data" type="application/json">(.*?)</script>', re.S
)


def embedded_data(path: pathlib.Path):
    """Pull the ti-data payload back out of an already-built report."""
    match = EMBEDDED.search(path.read_text(encoding="utf-8"))
    if not match:
        return None
    try:
        # '<' was escaped as <, which json.loads decodes natively.
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def summarise(data, date: str, filename: str) -> dict:
    """One timeline entry. Counts fall back to the entries themselves so a
    config without summary_statistics still produces a usable row."""
    entries = data.get("vulnerabilities", []) or []
    stats = data.get("summary_statistics", {}) or {}

    def count(key, predicate):
        value = stats.get(key)
        return value if isinstance(value, int) else sum(1 for e in entries if predicate(e))

    top = entries[0] if entries else {}
    return {
        "date": date,
        "file": filename,
        "check_performed_at": (data.get("report") or {}).get("check_performed_at"),
        "entries": len(entries),
        "actively_exploited": count(
            "actively_exploited",
            lambda e: e.get("exploitation_status") == "exploited_in_the_wild",
        ),
        "kev_listed": count("kev_listed", lambda e: bool(e.get("kev_listed"))),
        "no_patch": count("no_patch_available", lambda e: e.get("patch_available") == "no"),
        "cves": stats.get("total_cves_referenced")
        or len({c for e in entries for c in (e.get("cve_ids") or [])}),
        "headline": top.get("title", ""),
        "headline_status": top.get("exploitation_status"),
    }


def build_index(current_date=None, current_data=None, current_file=None) -> dict:
    """Index every dated report on disk, plus the one being written now."""
    rows = {}
    if REPORTS_DIR.is_dir():
        for path in sorted(REPORTS_DIR.glob("ti-report-*.html")):
            match = DATED_NAME.match(path.name)
            if not match:
                continue
            data = embedded_data(path)
            if data is not None:
                rows[match.group(1)] = summarise(data, match.group(1), path.name)

    # The report being built is not on disk yet (or is about to be overwritten),
    # so its row comes from the config rather than from a file read.
    if current_date and current_data is not None:
        rows[current_date] = summarise(current_data, current_date, current_file)

    ordered = [rows[key] for key in sorted(rows)]
    return {
        "generated_for": current_date or (ordered[-1]["date"] if ordered else None),
        "reports": ordered,
    }


def inline(value) -> str:
    """Serialise for embedding in a <script> block, with '<' neutralised so the
    payload can never terminate the host element."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace(
        "<", "\\u003c"
    )


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

    template = TEMPLATE.read_text(encoding="utf-8")
    for placeholder in (DATA_PLACEHOLDER, INDEX_PLACEHOLDER):
        if placeholder not in template:
            print(f"error: {TEMPLATE} has no {placeholder} placeholder", file=sys.stderr)
            return 1

    dated = DATED_NAME.match(out.name)
    index = build_index(
        current_date=dated.group(1) if dated else None,
        current_data=data if dated else None,
        current_file=out.name if dated else None,
    )

    rendered = template.replace(DATA_PLACEHOLDER, inline(data)).replace(
        INDEX_PLACEHOLDER, inline(index)
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    print(
        f"built {out.name}  "
        f"({len(data['vulnerabilities'])} entries, "
        f"{len(index['reports'])} in timeline, "
        f"{out.stat().st_size / 1024:.0f} KB)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
