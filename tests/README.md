# Unit Tests for OD-Translator

This directory contains unit tests for the OD-Translator project.

## Test Coverage

Total: **74 unit tests** + **10 realistic integration tests** = **84 total tests**

### test_parser.py (10 tests)
Tests for command normalization functionality in `src/core/parser.py`:
- Whitespace handling (basic, leading/trailing, tabs, newlines, mixed)
- Empty string handling
- Quote preservation
- Special character preservation

### test_detector.py (39 tests)
Tests for detection functions in `src/core/detector.py`:

**score_confidence() - 14 tests:**
- Evidence-based scoring (zero, single, duplicate, diverse evidence)
- Score clamping (0.0-1.0 range)
- Generic penalty application
- Category bonuses (chaining, download)
- Evidence count and diversity caps
- Score progression validation

Confidence scoring formula:
- Base confidence + evidence count bonus (0.06 per item, max 4)
- + category diversity bonus (0.07 per category, max 3)
- + chaining bonus (0.05 if present)
- + download bonus (0.05 if present)
- - generic penalty (0.04 if >=60% generic)

**detect_t1059() - 10 tests:**
- T1059.007 (JavaScript via mshta)
- T1059.005 (VBScript via mshta)
- Command execution in suspicious contexts
- No false positives on benign commands
- Evidence extraction and accumulation
- Confidence progression with more evidence
- Output structure validation
- Pattern suppression logic
- Indirect command execution detection

**detect_t1218() - 8 tests:**
- T1218.005 (mshta proxy execution)
- ActiveX object usage patterns
- rundll32 detection
- Evidence extraction and confidence scoring
- No false positives
- Output structure validation
- Network-related proxy patterns
- Multiple pattern detection

**detect_t1027() - 7 tests:**
- T1027.002 (Software packing tools: upx, themida)
- T1027.003 (Steganography: steghide)
- String concatenation obfuscation
- No false positives
- Evidence extraction
- Output structure validation
- Confidence scoring

### test_decoder.py (25 tests)
Tests for obfuscation detection and decoding in `src/core/decoder.py`:

**Encoding Detection (6 tests)**
- PowerShell base64 (`-encodedCommand`)
- JavaScript `fromCharCode()`
- JavaScript `atob()`
- URL encoding
- Multiple encoding detection
- No encoding detection

**Individual Decoders (12 tests)**
- PowerShell base64: simple, no encoding, invalid base64
- JavaScript atob: simple, multiple calls, no encoding
- fromCharCode: simple, complex, no encoding
- URL encoding: simple, mixed, no encoding

**Full Decoder Pipeline (7 tests)**
- No encoding
- PowerShell base64
- JavaScript atob
- fromCharCode
- URL encoding
- Multi-layer encoding
- Output structure validation

### test_realistic_commands.py (10 integration tests)
End-to-end integration tests using realistic "analyst headache" commands from `sample_commands.md`:

**Test Coverage:**
- Multi-technique attack chains (PowerShell → mshta → JavaScript → ActiveX)
- Direct WScript.Shell.Run execution
- Light obfuscation (string concatenation)
- Heavy obfuscation (PowerShell base64, JavaScript fromCharCode/atob)
- Extreme multi-layer obfuscation
- VBScript with Execute and command chaining
- Remote code download and local execution
- Multi-layer staging attacks

**Detection Performance:**
- T1059: 10/10 detected (100%)
- T1218: 8/8 detected (100%)
- Decoder: Successfully decoded 3/10 commands (base64, fromCharCode, atob)

These tests validate the full pipeline: decode → detect → analyze → score.

## Running Tests

### Run all unit tests
```bash
# Using simple runner (built-in)
python tests/test_parser.py      # 10 tests
python tests/test_detector.py    # 39 tests
python tests/test_decoder.py     # 25 tests

# Or run all at once
python tests/test_parser.py; python tests/test_detector.py; python tests/test_decoder.py
```

### Run realistic integration test
```bash
python tests/test_realistic_commands.py
```

This validates detection accuracy against real-world attack patterns with detailed output showing:
- Decoder performance (which encodings were detected/decoded)
- Detection results per command (techniques, confidence, evidence)
- Overall detection summary (success rate per technique)

### Run with pytest (if installed)
```bash
pytest tests/
pytest tests/test_parser.py -v
pytest tests/test_detector.py::test_score_confidence_zero_evidence
```

## Test Structure

Each test file includes:
1. Comprehensive docstrings explaining what's being tested
2. Simple built-in test runner (no dependencies)
3. Clear pass/fail output with counts
4. Exit code 0 for success, 1 for failure

## Adding New Tests

When adding new functionality to OD-Translator:

1. **Create test file** in `tests/` directory:
   ```python
   import sys
   from pathlib import Path
   
   src_root = Path(__file__).resolve().parent.parent / "src"
   sys.path.insert(0, str(src_root))
   
   from module import function_to_test
   ```

2. **Write test functions** with descriptive names:
   ```python
   def test_feature_specific_behavior():
       """Describe what this test verifies."""
       result = function_to_test(input_data)
       assert result == expected_value
   ```

3. **Add to test runner** at bottom of file:
   ```python
   if __name__ == "__main__":
       test_functions = [
           test_feature_specific_behavior,
           # ... more tests
       ]
       # ... runner code
   ```

## Expected Output

Successful test run:
```
✓ test_normalize_basic_whitespace
✓ test_normalize_leading_trailing
...
10 passed, 0 failed

✓ test_score_confidence_zero_evidence
✓ test_detect_t1059_mshta_javascript
...
24 passed, 0 failed

✓ test_detect_encoding_powershell_base64
...
25 passed, 0 failed
```

Failed test run:
```
✓ test_normalize_basic_whitespace
✗ test_normalize_leading_trailing: AssertionError
...
9 passed, 1 failed
```
