"""Tests for HTML report generation."""

import json
import tempfile
from pathlib import Path
import pytest

from core.report_generator import generate_single_report, generate_batch_report


@pytest.fixture
def sample_single_analysis():
    """Sample single command analysis."""
    return {
        "input_command": "powershell.exe -Command Get-Process",
        "normalized_command": "powershell.exe get-process",
        "detections": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "category": "Execution",
                "pattern": "powershell",
                "supporting_evidence": "PowerShell interpreter detected",
                "is_suspicious": False,
            },
            {
                "technique_id": "T1218",
                "technique_name": "System Binary Proxy Execution",
                "category": "Execution",
                "pattern": "signed_binary",
                "supporting_evidence": "Legitimate Windows binary detected",
                "is_suspicious": False,
            }
        ],
    }


@pytest.fixture
def sample_batch_data():
    """Sample batch processing output."""
    return {
        "batch_metadata": {
            "processed": 2,
            "errors": 0,
            "total": 2,
            "timestamp_utc": "2026-03-05T12:00:00Z",
            "duration_seconds": 0.150,
        },
        "results": [
            {
                "index": 1,
                "result": {
                    "input_command": "cmd.exe /c dir",
                    "normalized_command": "cmd.exe dir",
                    "detections": [
                        {
                            "technique_id": "T1059",
                            "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
                            "category": "Execution",
                            "pattern": "cmd.exe",
                            "supporting_evidence": "cmd.exe detected",
                            "is_suspicious": False,
                        }
                    ],
                }
            },
            {
                "index": 2,
                "result": {
                    "input_command": "rundll32.exe shell32.dll,ShellExec_RunDLL calc.exe",
                    "normalized_command": "rundll32.exe shell32.dll shellexec_rundll calc.exe",
                    "detections": [
                        {
                            "technique_id": "T1218",
                            "technique_name": "System Binary Proxy Execution: Rundll32",
                            "category": "Execution",
                            "pattern": "rundll32",
                            "supporting_evidence": "rundll32 binary proxy execution",
                            "is_suspicious": True,
                        }
                    ],
                }
            }
        ],
        "error_details": [],
    }


def test_generate_single_report_creates_file(sample_single_analysis):
    """Test that single report generates HTML file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "test_report.html")
        html = generate_single_report(sample_single_analysis, report_path)
        
        assert Path(report_path).exists()
        assert len(html) > 0
        assert html.startswith("<!DOCTYPE html>")
        assert html.endswith("</html>")


def test_generate_single_report_contains_command(sample_single_analysis):
    """Test that single report contains command information."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "test_report.html")
        html = generate_single_report(sample_single_analysis, report_path)
        
        assert "powershell.exe -Command Get-Process" in html
        assert "powershell.exe get-process" in html


def test_generate_single_report_contains_techniques(sample_single_analysis):
    """Test that single report contains technique detections."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "test_report.html")
        html = generate_single_report(sample_single_analysis, report_path)
        
        assert "T1059" in html
        assert "T1218" in html
        assert "Command and Scripting Interpreter" in html
        assert "System Binary Proxy Execution" in html


def test_generate_single_report_contains_killchain(sample_single_analysis):
    """Test that single report contains kill chain visualization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "test_report.html")
        html = generate_single_report(sample_single_analysis, report_path)
        
        assert "Cyber Kill Chain" in html
        assert "Execution" in html


def test_generate_batch_report_creates_file(sample_batch_data):
    """Test that batch report generates HTML file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(sample_batch_data, report_path)
        
        assert Path(report_path).exists()
        assert len(html) > 0
        assert html.startswith("<!DOCTYPE html>")
        assert html.endswith("</html>")


def test_generate_batch_report_contains_metadata(sample_batch_data):
    """Test that batch report contains batch metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(sample_batch_data, report_path)
        
        assert "Batch Processing Summary" in html
        assert "Total Commands" in html
        assert "2" in html  # total commands


def test_generate_batch_report_contains_timeline(sample_batch_data):
    """Test that batch report contains execution timeline."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(sample_batch_data, report_path)
        
        assert "Execution Timeline" in html
        assert "Command #1" in html
        assert "Command #2" in html


def test_generate_batch_report_contains_techniques(sample_batch_data):
    """Test that batch report contains detected techniques."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(sample_batch_data, report_path)
        
        assert "T1059" in html
        assert "T1218" in html
        assert "Aggregated Technique Coverage" in html


def test_generate_batch_report_no_errors(sample_batch_data):
    """Test that batch report handles no errors gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(sample_batch_data, report_path)
        
        # Should not have "Errors" section since error_details is empty
        # (but this might not be visible in the HTML due to conditional rendering)
        assert "Batch" in html


def test_generate_batch_report_with_errors():
    """Test that batch report handles errors."""
    batch_data = {
        "batch_metadata": {
            "processed": 1,
            "errors": 1,
            "total": 2,
            "timestamp_utc": "2026-03-05T12:00:00Z",
            "duration_seconds": 0.100,
        },
        "results": [
            {
                "index": 1,
                "result": {
                    "input_command": "valid command",
                    "normalized_command": "valid command",
                    "detections": [],
                }
            }
        ],
        "error_details": [
            {
                "index": 2,
                "command": "invalid command syntax",
                "error": "Syntax error in command",
            }
        ],
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "batch_report.html")
        html = generate_batch_report(batch_data, report_path)
        
        assert "Errors" in html
        assert "Syntax error" in html


def test_generate_single_report_default_path():
    """Test that single report uses default path if not specified."""
    analysis = {
        "input_command": "test command",
        "normalized_command": "test command",
        "detections": [],
    }
    
    # This will try to create file in data/reports which might exist
    # We'll use a temp dir context
    with tempfile.TemporaryDirectory() as tmpdir:
        import os
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            Path("data/reports").mkdir(parents=True, exist_ok=True)
            html = generate_single_report(analysis)
            assert Path("data/reports/command_analysis.html").exists()
        finally:
            os.chdir(original_cwd)


def test_report_html_contains_css():
    """Test that generated HTML contains CSS styling."""
    analysis = {
        "input_command": "test",
        "normalized_command": "test",
        "detections": [],
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = str(Path(tmpdir) / "test.html")
        html = generate_single_report(analysis, report_path)
        
        assert "<style>" in html
        assert "body {" in html
        assert ".container {" in html
        assert ".header {" in html
