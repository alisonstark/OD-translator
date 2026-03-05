import json
import os
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from core.batch_processor import load_batch_commands, process_batch_commands


def test_load_batch_commands_from_json_strings(tmp_path: Path):
    batch_file = tmp_path / "commands.json"
    batch_file.write_text(json.dumps(["whoami", "cmd.exe /c dir"]), encoding="utf-8")

    commands = load_batch_commands(str(batch_file))
    assert commands == ["whoami", "cmd.exe /c dir"]


def test_load_batch_commands_from_json_objects(tmp_path: Path):
    batch_file = tmp_path / "commands.json"
    batch_file.write_text(
        json.dumps([
            {"command": "powershell -c Get-Process"},
            {"command": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""},
        ]),
        encoding="utf-8",
    )

    commands = load_batch_commands(str(batch_file))
    assert len(commands) == 2
    assert commands[0].startswith("powershell")


def test_load_batch_commands_from_csv(tmp_path: Path):
    batch_file = tmp_path / "commands.csv"
    batch_file.write_text("command\nwhoami\ncmd.exe /c dir\n", encoding="utf-8")

    commands = load_batch_commands(str(batch_file))
    assert commands == ["whoami", "cmd.exe /c dir"]


def test_load_batch_commands_from_txt(tmp_path: Path):
    batch_file = tmp_path / "commands.txt"
    batch_file.write_text("whoami\n\ncmd.exe /c dir\n", encoding="utf-8")

    commands = load_batch_commands(str(batch_file))
    assert commands == ["whoami", "cmd.exe /c dir"]


def test_process_batch_commands_returns_structured_output():
    commands = [
        "powershell -c Get-Process",
        "cmd.exe /c dir",
    ]

    output = process_batch_commands(commands, decode=False, verbose=False)

    assert "batch_metadata" in output
    assert "results" in output
    assert "error_details" in output
    assert output["batch_metadata"]["total"] == 2
    assert output["batch_metadata"]["processed"] == 2
    assert output["batch_metadata"]["errors"] == 0
    assert len(output["results"]) == 2

    first_result = output["results"][0]
    assert "index" in first_result
    assert "result" in first_result
    assert "input_command" in first_result["result"]
    assert "normalized_command" in first_result["result"]
    assert "detections" in first_result["result"]
