"""
Unit tests for core.parser module - command normalization functionality.

These tests ensure that command normalization works correctly for various edge cases.
"""

import sys
from pathlib import Path

# Add src to path for imports
src_root = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_root))

from core.parser import normalize_command


def test_normalize_basic_whitespace():
    """Test basic whitespace collapsing."""
    assert normalize_command("cmd.exe    /c   whoami") == "cmd.exe /c whoami"


def test_normalize_leading_trailing():
    """Test leading and trailing whitespace removal."""
    assert normalize_command("  cmd.exe /c whoami  ") == "cmd.exe /c whoami"


def test_normalize_tabs():
    """Test tab character normalization."""
    assert normalize_command("cmd.exe\t/c\twhoami") == "cmd.exe /c whoami"


def test_normalize_newlines():
    """Test newline character handling."""
    assert normalize_command("cmd.exe\n/c\nwhoami") == "cmd.exe /c whoami"


def test_normalize_mixed_whitespace():
    """Test mixed whitespace character handling."""
    assert normalize_command("  cmd.exe  \t  /c  \n  whoami  ") == "cmd.exe /c whoami"


def test_normalize_empty_string():
    """Test empty string handling."""
    assert normalize_command("") == ""


def test_normalize_whitespace_only():
    """Test string with only whitespace."""
    assert normalize_command("   \t\n   ") == ""


def test_normalize_preserves_quotes():
    """Test that quotes are preserved (not normalized away)."""
    cmd = 'mshta.exe "javascript:var s=new ActiveXObject()"'
    assert '"javascript:var s=new ActiveXObject()"' in normalize_command(cmd)


def test_normalize_single_space():
    """Test that already normalized commands are unchanged."""
    cmd = "cmd.exe /c whoami"
    assert normalize_command(cmd) == cmd


def test_normalize_special_characters():
    """Test that special characters are preserved."""
    cmd = "cmd.exe /c echo $HOME && ls -la"
    assert normalize_command(cmd) == cmd


if __name__ == "__main__":
    # Simple test runner
    test_functions = [
        test_normalize_basic_whitespace,
        test_normalize_leading_trailing,
        test_normalize_tabs,
        test_normalize_newlines,
        test_normalize_mixed_whitespace,
        test_normalize_empty_string,
        test_normalize_whitespace_only,
        test_normalize_preserves_quotes,
        test_normalize_single_space,
        test_normalize_special_characters,
    ]
    
    passed = 0
    failed = 0
    
    for test in test_functions:
        try:
            test()
            print(f"✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed += 1
    
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
