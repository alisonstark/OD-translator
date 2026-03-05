import csv
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from core.pipeline import translate_command


def _utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _parse_json_batch(path: Path) -> List[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON batch input must be a list of commands or objects.")

    commands: List[str] = []
    for item in data:
        if isinstance(item, str):
            if item.strip():
                commands.append(item.strip())
            continue
        if isinstance(item, dict) and "command" in item and str(item["command"]).strip():
            commands.append(str(item["command"]).strip())
            continue
        raise ValueError("JSON batch entries must be strings or objects with a 'command' field.")
    return commands


def _parse_csv_batch(path: Path) -> List[str]:
    commands: List[str] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))

    if not rows:
        return commands

    header = [cell.strip().lower() for cell in rows[0]]
    if "command" in header:
        command_index = header.index("command")
        for row in rows[1:]:
            if not row or command_index >= len(row):
                continue
            value = (row[command_index] or "").strip()
            if value:
                commands.append(value)
        return commands

    for row in rows:
        if not row:
            continue
        value = (row[0] or "").strip()
        if value:
            commands.append(value)
    return commands


def _parse_text_batch(path: Path) -> List[str]:
    commands: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            commands.append(stripped)
    return commands


def load_batch_commands(batch_input_path: str) -> List[str]:
    path = Path(batch_input_path)
    if not path.exists():
        raise FileNotFoundError(f"Batch input file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        return _parse_json_batch(path)
    if suffix == ".csv":
        return _parse_csv_batch(path)
    return _parse_text_batch(path)


def process_batch_commands(
    commands: List[str],
    refresh_mitre: bool = False,
    decode: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    started = time.time()
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for index, command in enumerate(commands, start=1):
        try:
            result = translate_command(command, refresh_mitre=refresh_mitre, decode=decode)
            results.append({
                "index": index,
                "result": result,
            })
            if verbose:
                print(f"[{index}/{len(commands)}] processed")
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            errors.append(
                {
                    "index": index,
                    "command": command,
                    "error": str(exc),
                }
            )
            if verbose:
                print(f"[{index}/{len(commands)}] error: {exc}")

    duration = round(time.time() - started, 3)
    return {
        "batch_metadata": {
            "processed": len(results),
            "errors": len(errors),
            "total": len(commands),
            "timestamp_utc": _utc_now(),
            "duration_seconds": duration,
        },
        "results": results,
        "error_details": errors,
    }
