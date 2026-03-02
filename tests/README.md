# Unit Tests for OD-Translator

This directory contains unit tests for the OD-Translator project.

## Test Coverage

Total: **85 unit tests** + **1 integration test** = **86 total tests**

### test_parser.py (10 tests)
Tests for command normalization functionality in `src/core/parser.py`:
- Whitespace handling (basic, leading/trailing, tabs, newlines, mixed)
- Empty string handling
- Quote preservation
- Special character preservation

### test_detector.py (75 tests)
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

**detect_t1105() - 5 tests:**
- T1105 (Ingress Tool Transfer)
- PowerShell DownloadFile detection
- curl/wget download patterns
- XMLHTTP remote fetch via mshta
- No false positives on benign commands
- Output structure validation

**detect_t1071() - 6 tests:**
- T1071.001 (Application Layer Protocol - Web Protocols)
- HTTP/HTTPS URL detection in commands
- PowerShell Invoke-WebRequest patterns
- Suspicious TLD detection (.xyz, .top, .tk)
- IP address URL patterns
- No false positives on benign commands
- Output structure validation

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

### test_realistic_commands.py (1 integration test)
End-to-end integration test using realistic "analyst headache" commands from `sample_commands.md`:

**Test Coverage (10 commands tested):**
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

### Prerequisites
```bash
pip install pytest>=7.0.0
```

### Run All Tests
```bash
# Run all tests
pytest tests/

# Run all tests with verbose output
pytest tests/ -v

# Run all tests with extra verbosity (shows individual assertions)
pytest tests/ -vv
```

### Run Specific Test Files
```bash
pytest tests/test_parser.py      # 10 tests
pytest tests/test_detector.py    # 75 tests (14 confidence + 50 detection + 11 T1105/T1071)
pytest tests/test_decoder.py     # 25 tests
pytest tests/test_realistic_commands.py  # 1 integration test
```

### Run Specific Test Functions
```bash
# Run a single test function
pytest tests/test_detector.py::test_score_confidence_zero_evidence

# Run a specific class of tests
pytest tests/test_detector.py::TestDetector  # (if using test classes)
```

### Targeted Test Filtering with `-k`
```bash
# Run all T1105 and T1071 tests
pytest tests/test_detector.py -k "t1105 or t1071"

# Run all confidence scoring tests
pytest tests/test_detector.py -k "confidence"

# Run all encoding detection tests
pytest tests/test_decoder.py -k "detect_encoding"

# Exclude specific tests
pytest tests/ -k "not realistic"
```

### Useful Pytest Options
```bash
# Stop on first failure
pytest tests/ -x

# Show local variables on failure
pytest tests/ -l

# Show short traceback
pytest tests/ --tb=short

# Show full traceback
pytest tests/ --tb=long

# Show only failed tests
pytest tests/ --failed-first

# Quiet mode (only show dots)
pytest tests/ -q

# Show print statements
pytest tests/ -s
```

### Watch Mode (Re-run on file changes)
```bash
# Requires pytest-watch
pip install pytest-watch
ptw tests/
```

### Example Output
```bash
$ pytest tests/ -v
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 86 items

tests/test_decoder.py::test_detect_encoding_powershell_base64 PASSED     [  1%]
tests/test_decoder.py::test_decode_powershell_base64_simple PASSED       [  8%]
...
tests/test_detector.py::test_score_confidence_zero_evidence PASSED       [ 30%]
tests/test_detector.py::test_detect_t1059_mshta_javascript PASSED        [ 46%]
tests/test_detector.py::test_detect_t1105_curl_download_output PASSED    [ 76%]
tests/test_detector.py::test_detect_t1071_http_url_in_command PASSED     [ 81%]
...
tests/test_parser.py::test_normalize_basic_whitespace PASSED             [ 88%]
tests/test_realistic_commands.py::test_realistic_commands PASSED         [100%]

============================= 86 passed in 0.30s ==============================
```

## Test Structure

Each test file includes:
1. Comprehensive docstrings explaining what's being tested
2. Standard pytest test functions (prefixed with `test_`)
3. Clear assertions with descriptive error messages
4. Isolated tests with no side effects or dependencies between tests

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

3. **Run the new tests**:
   ```bash
   # Run your new test file
   pytest tests/test_yourmodule.py -v
   
   # Or run a specific test function
   pytest tests/test_yourmodule.py::test_feature_specific_behavior -v
   ```

## Integration Test Details

The `test_realistic_commands.py` integration test validates detection accuracy against real-world attack patterns with detailed output showing:
- Decoder performance (which encodings were detected/decoded)
- Detection results per command (techniques, confidence, evidence)
- Overall detection summary (success rate per technique)

**Detection Performance:**
- T1059: 10/10 detected (100%)
- T1218: 8/8 detected (100%)
- Decoder: Successfully decoded 3/10 commands (base64, fromCharCode, atob)

## Expected Test Output

### Successful Test Run
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 86 items

tests/test_decoder.py::test_detect_encoding_powershell_base64 PASSED     [  1%]
tests/test_decoder.py::test_decode_powershell_base64_simple PASSED       [  8%]
...
tests/test_detector.py::test_score_confidence_zero_evidence PASSED       [ 30%]
tests/test_parser.py::test_normalize_basic_whitespace PASSED             [ 88%]
tests/test_realistic_commands.py::test_realistic_commands PASSED         [100%]

============================= 86 passed in 0.30s ==============================
```

### Failed Test Run
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 86 items

tests/test_detector.py::test_score_confidence_zero_evidence PASSED       [ 30%]
tests/test_detector.py::test_detect_t1059_mshta_javascript FAILED        [ 31%]

================================== FAILURES ===================================
______________________ test_detect_t1059_mshta_javascript ______________________

    def test_detect_t1059_mshta_javascript():
        """Test T1059.007 detection for JavaScript via mshta."""
        cmd = "mshta.exe javascript:alert('test')"
        detections = detect_t1059(cmd)
    
>       assert len(detections) > 0
E       AssertionError: assert 0 > 0
E        +  where 0 = len([])

tests/test_detector.py:123: AssertionError
======================= 1 failed, 85 passed in 0.35s ========================
```
