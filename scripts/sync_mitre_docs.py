import argparse
import json
import os
import re
from datetime import datetime, timezone, timedelta
from html import unescape
from typing import Dict, List, Tuple
from urllib.request import Request, urlopen

USER_AGENT = "ODT-MITRE-Docs-Sync/1.0"
DEFAULT_TIMEOUT = 20
DEFAULT_OUTPUT_DIR = os.path.join("data", "mitre_docs")
DEFAULT_TECHNIQUES = ["T1027", "T1055", "T1059", "T1071", "T1105", "T1218", "T1543"]
DEFAULT_STALENESS_DAYS = 30


def _utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _normalize_technique_ids(technique_ids: List[str]) -> List[str]:
    normalized = []
    seen = set()
    for technique_id in technique_ids:
        technique_id = (technique_id or "").strip().upper()
        if not technique_id:
            continue
        if not re.match(r"^T\d{4}$", technique_id):
            raise ValueError("Invalid technique ID: {0}. Expected format like T1105.".format(technique_id))
        if technique_id in seen:
            continue
        seen.add(technique_id)
        normalized.append(technique_id)
    return sorted(normalized)


def _techniques_from_rules() -> List[str]:
    import sys

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    src_root = os.path.join(project_root, "src")
    if src_root not in sys.path:
        sys.path.insert(0, src_root)

    from detection.technique_pattern_db import RULES

    ids = set()
    for rule in RULES:
        technique = rule.get("technique")
        if technique and re.match(r"^T\d{4}$", technique):
            ids.add(technique)
    return sorted(ids)


def _fetch_html(url: str, timeout: int) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _extract_title(html_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return unescape(re.sub(r"\s+", " ", match.group(1)).strip())


def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


def _html_to_markdown(html_text: str, technique_id: str, source_url: str, title: str) -> str:
    main_match = re.search(r"<main[^>]*>(.*?)</main>", html_text, flags=re.IGNORECASE | re.DOTALL)
    content = main_match.group(1) if main_match else html_text

    content = re.sub(r"<script[^>]*>.*?</script>", "", content, flags=re.IGNORECASE | re.DOTALL)
    content = re.sub(r"<style[^>]*>.*?</style>", "", content, flags=re.IGNORECASE | re.DOTALL)

    for level in [1, 2, 3, 4, 5, 6]:
        pattern = r"<h{0}[^>]*>(.*?)</h{0}>".format(level)

        def _heading_repl(match):
            raw = _strip_tags(match.group(1)).strip()
            if not raw:
                return ""
            return "\n{0} {1}\n".format("#" * level, unescape(raw))

        content = re.sub(pattern, _heading_repl, content, flags=re.IGNORECASE | re.DOTALL)

    def _li_repl(match):
        raw = _strip_tags(match.group(1)).strip()
        return "\n- {0}".format(unescape(raw)) if raw else ""

    content = re.sub(r"<li[^>]*>(.*?)</li>", _li_repl, content, flags=re.IGNORECASE | re.DOTALL)
    content = re.sub(r"<br\s*/?>", "\n", content, flags=re.IGNORECASE)
    content = re.sub(r"</p>", "\n\n", content, flags=re.IGNORECASE)
    content = re.sub(r"<p[^>]*>", "", content, flags=re.IGNORECASE)

    text = unescape(_strip_tags(content))
    text = re.sub(r"\r", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = text.strip()

    header = [
        "# {0} - MITRE ATT&CK Technique Documentation".format(technique_id),
        "",
        "- Source: {0}".format(source_url),
        "- Retrieved (UTC): {0}".format(_utc_now()),
    ]
    if title:
        header.append("- Source Title: {0}".format(title))
    header.append("")
    header.append("---")
    header.append("")

    return "\n".join(header) + text + "\n"


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _write_manifest(output_dir: str, records: List[Dict[str, str]]) -> None:
    manifest = {
        "generated_at_utc": _utc_now(),
        "records": records,
    }
    manifest_path = os.path.join(output_dir, "manifest.json")
    _write_file(manifest_path, json.dumps(manifest, indent=2))


def _parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO 8601 UTC timestamp (e.g., '2026-03-02T16:49:05Z') to datetime."""
    if not timestamp_str:
        return None
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _is_stale(timestamp_str: str, days_threshold: int = DEFAULT_STALENESS_DAYS) -> bool:
    """Check if a cached document is older than days_threshold."""
    ts = _parse_timestamp(timestamp_str)
    if not ts:
        return True  # Missing timestamp = stale
    
    age = datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc)
    return age > timedelta(days=days_threshold)


def _check_staleness(output_dir: str, days_threshold: int = DEFAULT_STALENESS_DAYS) -> Tuple[List[str], List[str]]:
    """Check manifest for stale documents. Returns (stale_ids, fresh_ids)."""
    manifest_path = os.path.join(output_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return [], []
    
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, IOError):
        return [], []
    
    stale = []
    fresh = []
    for record in manifest.get("records", []):
        technique_id = record.get("technique_id")
        if not technique_id:
            continue
        timestamp = record.get("retrieved_at_utc")
        if _is_stale(timestamp, days_threshold):
            stale.append(technique_id)
        else:
            fresh.append(technique_id)
    
    return stale, fresh


def _write_index_readme(output_dir: str, records: List[Dict[str, str]]) -> None:
    lines = [
        "# MITRE ATT&CK Technique Docs (Offline Cache)",
        "",
        "Authoritative source pages are downloaded from the official MITRE ATT&CK website and stored locally.",
        "",
        "## Update",
        "",
        "```bash",
        "python scripts/sync_mitre_docs.py --all-from-rules --format both",
        "```",
        "",
        "## Check Staleness",
        "",
        "Check if cached docs are older than 30 days:",
        "```bash",
        "python scripts/sync_mitre_docs.py --check-staleness",
        "```",
        "",
        "Automatically update stale docs:",
        "```bash",
        "python scripts/sync_mitre_docs.py --update-stale",
        "```",
        "",
        "## Techniques",
        "",
        "| Technique | Source URL | HTML | Markdown | Retrieved (UTC) |",
        "|---|---|---|---|---|",
    ]

    for record in records:
        html_path = record.get("html_path") or "-"
        md_path = record.get("markdown_path") or "-"
        lines.append(
            "| {0} | {1} | {2} | {3} | {4} |".format(
                record["technique_id"],
                record["source_url"],
                html_path,
                md_path,
                record["retrieved_at_utc"],
            )
        )

    lines.append("")
    _write_file(os.path.join(output_dir, "README.md"), "\n".join(lines))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download official MITRE ATT&CK technique pages for offline use and optional Markdown conversion."
    )
    parser.add_argument(
        "--techniques",
        type=str,
        default=",".join(DEFAULT_TECHNIQUES),
        help="Comma-separated technique IDs (e.g., T1059,T1105). Ignored when --all-from-rules is used.",
    )
    parser.add_argument(
        "--all-from-rules",
        action="store_true",
        help="Auto-discover technique IDs from src/detection/technique_pattern_db.py.",
    )
    parser.add_argument(
        "--format",
        choices=["html", "markdown", "both"],
        default="both",
        help="Output format to generate.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="Base output directory for cached docs.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="HTTP timeout in seconds for each MITRE request.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite files even if they already exist.",
    )
    parser.add_argument(
        "--check-staleness",
        action="store_true",
        help="Check if cached docs are older than 30 days and report staleness.",
    )
    parser.add_argument(
        "--update-stale",
        action="store_true",
        help="Automatically update any cached docs older than 30 days.",
    )
    parser.add_argument(
        "--staleness-days",
        type=int,
        default=DEFAULT_STALENESS_DAYS,
        help="Threshold in days for considering docs stale (default: 30).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = os.path.abspath(args.output_dir)
    
    # Handle staleness check
    if args.check_staleness:
        stale, fresh = _check_staleness(output_dir, args.staleness_days)
        print("\n[Staleness Report]")
        if stale:
            print(f"[!] STALE (>{args.staleness_days} days): {', '.join(stale)}")
        if fresh:
            print(f"[+] FRESH (<={args.staleness_days} days): {', '.join(fresh)}")
        if not stale and not fresh:
            print("No cached docs found. Run sync to populate cache.")
        return 0
    
    # Handle auto-update of stale docs
    if args.update_stale:
        stale, fresh = _check_staleness(output_dir, args.staleness_days)
        if stale:
            print(f"[!] Found {len(stale)} stale technique(s): {', '.join(stale)}")
            args.techniques = ",".join(stale)
            args.force = True  # Force re-download stale docs
            print(f"[*] Auto-updating stale docs...")
        else:
            print("[+] All cached docs are fresh. No update needed.")
            return 0
    
    if args.all_from_rules:
        technique_ids = _techniques_from_rules()
    else:
        technique_ids = _normalize_technique_ids(args.techniques.split(","))

    if not technique_ids:
        raise SystemExit("No technique IDs to process.")

    html_dir = os.path.join(output_dir, "html")
    markdown_dir = os.path.join(output_dir, "markdown")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    os.makedirs(markdown_dir, exist_ok=True)

    records = []

    for technique_id in technique_ids:
        source_url = "https://attack.mitre.org/techniques/{0}/".format(technique_id)
        html_path = os.path.join(html_dir, "{0}.html".format(technique_id))
        md_path = os.path.join(markdown_dir, "{0}.md".format(technique_id))

        need_html = args.format in ("html", "both")
        need_md = args.format in ("markdown", "both")

        skip_fetch = (
            not args.force
            and ((not need_html or os.path.exists(html_path)) and (not need_md or os.path.exists(md_path)))
        )

        if skip_fetch:
            print("[skip] {0} (already present)".format(technique_id))
            records.append(
                {
                    "technique_id": technique_id,
                    "source_url": source_url,
                    "html_path": os.path.relpath(html_path, output_dir).replace("\\", "/") if os.path.exists(html_path) else "",
                    "markdown_path": os.path.relpath(md_path, output_dir).replace("\\", "/") if os.path.exists(md_path) else "",
                    "retrieved_at_utc": _utc_now(),
                    "source_title": "",
                }
            )
            continue

        print("[fetch] {0} -> {1}".format(technique_id, source_url))
        html_text = _fetch_html(source_url, timeout=args.timeout)
        title = _extract_title(html_text)

        if need_html:
            _write_file(html_path, html_text)

        if need_md:
            markdown_text = _html_to_markdown(
                html_text=html_text,
                technique_id=technique_id,
                source_url=source_url,
                title=title,
            )
            _write_file(md_path, markdown_text)

        records.append(
            {
                "technique_id": technique_id,
                "source_url": source_url,
                "html_path": os.path.relpath(html_path, output_dir).replace("\\", "/") if need_html else "",
                "markdown_path": os.path.relpath(md_path, output_dir).replace("\\", "/") if need_md else "",
                "retrieved_at_utc": _utc_now(),
                "source_title": title,
            }
        )

    _write_manifest(output_dir, records)
    _write_index_readme(output_dir, records)

    print("\nSynced {0} technique documents into {1}".format(len(records), output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
