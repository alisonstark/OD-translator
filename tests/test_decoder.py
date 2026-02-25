"""
Unit tests for core.decoder module - obfuscation detection and decoding.

These tests ensure that the decoder correctly identifies and decodes various
obfuscation techniques including base64, fromCharCode, atob, and URL encoding.
"""

import sys
from pathlib import Path

# Add src to path for imports
src_root = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_root))

from core.decoder import (
    detect_encoding_types,
    decode_powershell_base64,
    decode_javascript_atob,
    decode_fromcharcode,
    decode_url_encoding,
    decode_command
)


# ===== Encoding Detection Tests =====

def test_detect_encoding_powershell_base64():
    """Test detection of PowerShell base64 encoding."""
    cmd = "powershell.exe -encodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
    encodings = detect_encoding_types(cmd)
    assert "powershell_base64" in encodings


def test_detect_encoding_javascript_fromcharcode():
    """Test detection of JavaScript fromCharCode encoding."""
    cmd = "mshta javascript:String.fromCharCode(118,97,114)"
    encodings = detect_encoding_types(cmd)
    assert "charcode" in encodings


def test_detect_encoding_javascript_atob():
    """Test detection of JavaScript atob encoding."""
    cmd = "mshta javascript:eval(atob('dmFyIHM9bmV3IEFQ'))"
    encodings = detect_encoding_types(cmd)
    assert "javascript_atob" in encodings


def test_detect_encoding_url():
    """Test detection of URL encoding."""
    cmd = "mshta.exe%20javascript%3Avar%20s%3Dnew"
    encodings = detect_encoding_types(cmd)
    assert "url_encoding" in encodings


def test_detect_encoding_multiple():
    """Test detection of multiple encoding types."""
    # Need longer base64 to meet 20 char minimum
    cmd = "powershell -encodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA== | mshta javascript:atob('test')"
    encodings = detect_encoding_types(cmd)
    assert "powershell_base64" in encodings
    assert "javascript_atob" in encodings


def test_detect_encoding_none():
    """Test detection with no encoding."""
    cmd = "cmd.exe /c whoami"
    encodings = detect_encoding_types(cmd)
    assert len(encodings) == 0


# ===== PowerShell Base64 Decoding Tests =====

def test_decode_powershell_base64_simple():
    """Test PowerShell base64 decoding with simple command."""
    # "Get-Process" in UTF-16LE base64
    cmd = "powershell -encodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
    result, was_decoded = decode_powershell_base64(cmd)
    assert was_decoded is True
    assert "get-process" in result.lower()


def test_decode_powershell_base64_no_encoding():
    """Test PowerShell base64 decoding when no encoded command present."""
    cmd = "powershell Get-Process"
    result, was_decoded = decode_powershell_base64(cmd)
    assert was_decoded is False
    assert result == cmd


def test_decode_powershell_base64_invalid():
    """Test PowerShell base64 decoding with invalid base64."""
    # Need 20+ chars for detection even if invalid
    cmd = "powershell -encodedCommand !!!INVALID_BUT_LONG_ENOUGH!!!"
    result, was_decoded = decode_powershell_base64(cmd)
    # Should return original if decoding fails
    assert was_decoded is False
    assert result == cmd


# ===== JavaScript atob Decoding Tests =====

def test_decode_javascript_atob_simple():
    """Test JavaScript atob decoding."""
    # "var s=new" in base64
    cmd = "mshta javascript:eval(atob('dmFyIHM9bmV3'))"
    result, was_decoded = decode_javascript_atob(cmd)
    assert was_decoded is True
    assert "var s=new" in result


def test_decode_javascript_atob_multiple():
    """Test JavaScript atob with multiple atob calls."""
    cmd = "atob('dGVzdA==') + atob('ZGF0YQ==')"
    result, was_decoded = decode_javascript_atob(cmd)
    assert was_decoded is True
    assert "test" in result or "data" in result


def test_decode_javascript_atob_no_encoding():
    """Test JavaScript atob when no atob present."""
    cmd = "mshta javascript:alert('test')"
    result, was_decoded = decode_javascript_atob(cmd)
    assert was_decoded is False
    assert result == cmd


# ===== fromCharCode Decoding Tests =====

def test_decode_fromcharcode_simple():
    """Test fromCharCode decoding with simple char codes."""
    # "var" = 118,97,114
    cmd = "String.fromCharCode(118,97,114)"
    result, was_decoded = decode_fromcharcode(cmd)
    assert was_decoded is True
    assert "var" in result


def test_decode_fromcharcode_complex():
    """Test fromCharCode with complex command."""
    # "eval" = 101,118,97,108
    cmd = "mshta javascript:eval(String.fromCharCode(101,118,97,108))"
    result, was_decoded = decode_fromcharcode(cmd)
    assert was_decoded is True
    assert "eval" in result


def test_decode_fromcharcode_no_encoding():
    """Test fromCharCode when not present."""
    cmd = "mshta javascript:alert('test')"
    result, was_decoded = decode_fromcharcode(cmd)
    assert was_decoded is False
    assert result == cmd


# ===== URL Decoding Tests =====

def test_decode_url_encoding_simple():
    """Test URL decoding."""
    cmd = "mshta.exe%20javascript%3Avar"
    result, was_decoded = decode_url_encoding(cmd)
    assert was_decoded is True
    assert "mshta.exe javascript:var" in result


def test_decode_url_encoding_mixed():
    """Test URL decoding with mixed encoded/plain text."""
    cmd = "cmd.exe%20/c%20whoami"
    result, was_decoded = decode_url_encoding(cmd)
    assert was_decoded is True
    assert "cmd.exe /c whoami" in result


def test_decode_url_encoding_none():
    """Test URL decoding with no encoding."""
    cmd = "cmd.exe /c whoami"
    result, was_decoded = decode_url_encoding(cmd)
    assert was_decoded is False
    assert result == cmd


# ===== Full decode_command Tests =====

def test_decode_command_no_encoding():
    """Test decode_command with plain command."""
    cmd = "cmd.exe /c whoami"
    result = decode_command(cmd)
    assert result["original"] == cmd
    assert result["decoded"] == cmd
    assert result["was_decoded"] is False
    assert len(result["encodings_detected"]) == 0


def test_decode_command_powershell_base64():
    """Test decode_command with PowerShell base64."""
    # "Get-Process" in UTF-16LE base64
    cmd = "powershell -encodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
    result = decode_command(cmd)
    assert result["was_decoded"] is True
    assert "powershell_base64" in result["encodings_detected"]
    assert "get-process" in result["decoded"].lower()


def test_decode_command_javascript_atob():
    """Test decode_command with JavaScript atob."""
    cmd = "mshta javascript:eval(atob('dGVzdA=='))"
    result = decode_command(cmd)
    assert result["was_decoded"] is True
    assert "javascript_atob" in result["encodings_detected"]
    assert "test" in result["decoded"]


def test_decode_command_fromcharcode():
    """Test decode_command with fromCharCode."""
    cmd = "String.fromCharCode(118,97,114)"
    result = decode_command(cmd)
    assert result["was_decoded"] is True
    assert "charcode" in result["encodings_detected"]
    assert "var" in result["decoded"]


def test_decode_command_url_encoding():
    """Test decode_command with URL encoding."""
    cmd = "mshta.exe%20javascript%3Atest"
    result = decode_command(cmd)
    assert result["was_decoded"] is True
    assert "url_encoding" in result["encodings_detected"]
    assert "mshta.exe javascript:test" in result["decoded"]


def test_decode_command_multi_layer():
    """Test decode_command with multiple encoding layers."""
    # URL encoded atob
    cmd = "javascript%3Aatob('dGVzdA==')"
    result = decode_command(cmd)
    assert result["was_decoded"] is True
    # Should detect both encodings
    assert "url_encoding" in result["encodings_detected"]
    # Should decode both layers
    assert "test" in result["decoded"]


def test_decode_command_structure():
    """Test decode_command returns proper structure."""
    cmd = "test"
    result = decode_command(cmd)
    
    # Verify all required keys are present
    assert "original" in result
    assert "decoded" in result
    assert "encodings_detected" in result
    assert "encodings_decoded" in result
    assert "was_decoded" in result
    
    # Verify types
    assert isinstance(result["original"], str)
    assert isinstance(result["decoded"], str)
    assert isinstance(result["encodings_detected"], list)
    assert isinstance(result["encodings_decoded"], list)
    assert isinstance(result["was_decoded"], bool)


if __name__ == "__main__":
    # Simple test runner
    test_functions = [
        test_detect_encoding_powershell_base64,
        test_detect_encoding_javascript_fromcharcode,
        test_detect_encoding_javascript_atob,
        test_detect_encoding_url,
        test_detect_encoding_multiple,
        test_detect_encoding_none,
        test_decode_powershell_base64_simple,
        test_decode_powershell_base64_no_encoding,
        test_decode_powershell_base64_invalid,
        test_decode_javascript_atob_simple,
        test_decode_javascript_atob_multiple,
        test_decode_javascript_atob_no_encoding,
        test_decode_fromcharcode_simple,
        test_decode_fromcharcode_complex,
        test_decode_fromcharcode_no_encoding,
        test_decode_url_encoding_simple,
        test_decode_url_encoding_mixed,
        test_decode_url_encoding_none,
        test_decode_command_no_encoding,
        test_decode_command_powershell_base64,
        test_decode_command_javascript_atob,
        test_decode_command_fromcharcode,
        test_decode_command_url_encoding,
        test_decode_command_multi_layer,
        test_decode_command_structure,
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
