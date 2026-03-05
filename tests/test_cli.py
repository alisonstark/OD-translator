"""CLI argument and execution integration tests."""

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = ROOT / ".venv" / "Scripts" / "python.exe"


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PYTHON_EXE), "src/cli/main.py", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_help_includes_batch_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    assert "--batch-input" in result.stdout
    assert "--batch-output" in result.stdout
    assert "--batch-verbose" in result.stdout


def test_cli_rejects_removed_secondary_flag():
    result = _run_cli(["--include-secondary-techniques", "whoami"])
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_cli_batch_input_writes_single_aggregated_output(tmp_path: Path):
    batch_input = tmp_path / "commands.txt"
    batch_input.write_text("whoami\ncmd.exe /c dir\n", encoding="utf-8")

    output_name = "cli_batch_test_output.json"
    output_file = ROOT / "data" / "results" / output_name
    if output_file.exists():
        output_file.unlink()

    result = _run_cli([
        "--batch-input",
        str(batch_input),
        "--batch-output",
        output_name,
    ])

    try:
        assert result.returncode == 0
        assert output_file.exists()

        payload = json.loads(output_file.read_text(encoding="utf-8"))
        assert "batch_metadata" in payload
        assert "results" in payload
        assert payload["batch_metadata"]["total"] == 2
        assert len(payload["results"]) == 2
    finally:
        if output_file.exists():
            output_file.unlink()
