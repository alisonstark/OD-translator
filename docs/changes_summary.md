# Changes Summary (Multi-technique Pipeline + attackcti)

Date: 2026-03-04

## Phase 4: Professional HTML Report Generation

### HTML Report Module (`src/core/report_generator.py`)
- **Single Command Reports**: Professional HTML analysis for individual command forensics
  - Input and normalized command display
  - Detected techniques with expandable details
  - Kill-chain phase visualization (0-8 phases mapped to MITRE techniques)
  - Interactive technique cards with evidence and pattern matching
  - Embedded CSS styling with responsive design

- **Batch Analysis Reports**: Comprehensive batch analysis with timeline and aggregation
  - Batch processing metadata (total, processed, errors, duration)
  - Execution timeline with risk indicators (high-risk command highlighting)
  - Aggregated technique coverage table (cross-command detection summary)
  - Per-command detailed analysis sections
  - Error tracking and diagnostics
  - Kill-chain progression visualization

- **HTML Features**:
  - Professional gradient header and responsive layout
  - Embedded CSS (dark theme, accessibility-friendly colors)
  - Interactive JavaScript: clickable cards expand/collapse details
  - Kill-chain phase mapping: displays all 9 MITRE phases with active techniques highlighted
  - Timestamp and generation metadata in footer
  - Export-friendly (can be saved, emailed, printed)

### CLI Integration (`src/cli/main.py`)
- New flags:
  - `--generate-report`: Enable HTML report generation
  - `--report-output <path>`: Custom report output path (optional)
- Behavior:
  - Single command: `odt --generate-report "cmd.exe /c dir"` → saves to `data/reports/analysis_TIMESTAMP.html`
  - Batch mode: `odt --batch-input commands.txt --generate-report` → saves batch report alongside JSON
  - Report generation is opt-in (default: JSON only)

### Report Output Structure
- **Default paths**: 
  - Single: `data/reports/analysis_YYYYMMDD_HHMMSS.html`
  - Batch: `data/reports/batch_YYYYMMDD_HHMMSS.html`
- **Customizable**: `--report-output my_report.html` to override defaults

### Testing Additions
- Added `tests/test_report_generator.py` (12 tests):
  - Single report creation and content validation (4 tests)
  - Batch report creation, metadata, timeline, technique aggregation (5 tests)
  - HTML structure and CSS validation (3 tests)
- **Test count update**: 144 total tests (117 unit + 27 integration/benign), 100% pass rate

### Documentation Updates
- Updated `README.md` with HTML report section and usage examples
- Updated `tests/README.md` with report generator test documentation
- Updated project structure to show `test_report_generator.py`
- Updated `TODO.md` to document Phase 4 completion

---

Date: 2026-03-04

## Phase 3 Kickoff: All-Techniques-by-Default + Installable CLI + Batch Mode

### Architecture Refactor: Removed Primary/Secondary Technique Split
- **Behavior change**: Removed T1059-centric/secondary-technique execution model from runtime flow.
- **Pipeline update** (`src/core/pipeline.py`):
  - Removed `include_secondary_techniques` parameter from `translate_command()`.
  - Added `ALL_TECHNIQUES = [T1059, T1218, T1027, T1105, T1071, T1543, T1055]` and evaluate all on every command.
  - MITRE cache warm-up now happens for all command analyses.
- **CLI update** (`src/cli/main.py`):
  - Removed `--include-secondary-techniques` flag.
  - Updated CLI description/help to reflect all-techniques default behavior.
- **Documentation update** (`README.md`, `docs/cyber_kill_chain_mapping.md`):
  - Removed “Primary vs Secondary” framing.
  - Updated command examples to current default behavior.

### Installable Package Support (`odt` command)
- Added `pyproject.toml` with setuptools build configuration.
- Added console script entry point:
  - `odt = "cli.main:main"`
- Install commands now supported:
  - `pip install -e .` (editable)
  - `pip install .` (environment install)
- Verified executable help output via `.venv\Scripts\odt.exe --help`.

### Batch Command Processing Feature
- Added new batch processor module: `src/core/batch_processor.py`.
- Supported batch input formats:
  - `.txt` (one command per line)
  - `.csv` (first column or explicit `command` header)
  - `.json` (list of strings or list of objects with `command` field)
- Added CLI flags:
  - `--batch-input <path>`
  - `--batch-output <filename>`
  - `--batch-verbose`
- Batch output now produces a **single aggregated JSON file** with:
  - `batch_metadata`
  - `results`
  - `error_details`

### Root-Level Batch Examples Added
- Added example input files in repository root (next to `sample_commands.md`):
  - `batch_commands_example.txt`
  - `batch_commands_example.csv`
  - `batch_commands_example.json`
- Added README examples showing direct usage of these files.

### Testing Additions
- Added `tests/test_batch_processor.py` (5 tests): parsing and batch output shape.
- Added `tests/test_cli.py` (3 tests): batch flags in help, removed legacy flag rejection, batch output file generation.
- **Test count update**: 132 total tests passing in `.venv`.

Date: 2026-03-02

## Phase 2 Extension: T1543 & T1055 Detection Implementation

### T1543 (Create or Modify System Process) - Persistence via System Processes
- **Technique Overview**: Windows/Linux-based persistence through service manipulation (T1543.003 Windows Service, T1543.004 Launch Daemon, T1543.005 systemd)
- **Detection Patterns** (8 patterns added to `technique_pattern_db.py`):
  - PowerShell `New-Service` cmdlet with suspicious binary paths
  - `sc.exe create` service creation commands
  - Registry-based service modification (`HKLM:\System\CurrentControlSet\Services\`)
  - Suspicious service binary paths
  - macOS launchd plist file creation/modification
  - systemd unit file creation on Linux
  - Registry persistence mechanisms
- **Detector Function**: Added `detect_t1543()` in `src/core/detector.py`
- **Metadata Enrichment** (5 entries): Telemetry sources (Event ID 4697 for service creation, registry auditing), SOC analysis guidance
- **Unit Tests** (5 tests in `test_detector.py`):
  - PowerShell service creation detection
  - sc.exe service creation detection
  - Registry modification detection
  - False-positive baseline (benign Get-Service commands)
  - Output structure validation
- **Sample Commands**: Added 4 realistic T1543 attack examples in `sample_commands.md`:
  - PowerShell backdoor service with beacon callback
  - sc.exe hidden service creation
  - Registry-based service binary hijacking
  - Suspicious service targeting system processes
- **Cyber Kill Chain Mapping**: Demonstrates **Persistence** and **Privilege Escalation** stages

### T1055 (Process Injection) - Code Execution & Evasion
- **Technique Overview**: Inject code into running processes to evade detection (T1055.001 DLL Injection, T1055.002 Portable Executable Injection, T1055.012 Process Hollowing)
- **Detection Patterns** (6 patterns added to `technique_pattern_db.py`):
  - `CreateRemoteThread` API calls (classic DLL injection signature)
  - `Invoke-ReflectivePEInjection` PowerShell patterns
  - `Invoke-DllInjection` post-exploitation frameworks
  - Process hollowing patterns (CreateProcess SUSPENDED + WriteProcessMemory)
  - `LoadLibrary` + `CreateRemoteThread` injection chains
  - Suspicious target process detection (explorer.exe, svchost.exe, lsass.exe)
- **Detector Function**: Added `detect_t1055()` in `src/core/detector.py`
- **Metadata Enrichment** (11 entries): Telemetry sources (ETW providers, memory forensics, API hooking), detection opportunities, high-value target indicators
- **Unit Tests** (7 tests in `test_detector.py`):
  - CreateRemoteThread API pattern detection
  - Invoke-ReflectivePEInjection detection
  - Invoke-DllInjection detection
  - LoadLibrary injection chain detection
  - Suspicious target process injection detection
  - False-positive baseline
  - Output structure validation
- **Sample Commands**: Added 6 realistic T1055 attack examples in `sample_commands.md`:
  - Reflective PE injection with in-memory shellcode
  - Classic DLL injection via CreateRemoteThread
  - Process hollowing with suspended process
  - svchost.exe injection targeting
  - Multi-stage injection chains (download DLL → inject)
  - Invoke-DllInjection post-exploitation pattern
- **Cyber Kill Chain Mapping**: Demonstrates **Execution** and **Defense Evasion** stages

### Testing Infrastructure Updates
- **Unit Test Expansion**: Added 12 new tests (5 T1543 + 7 T1055) to `tests/test_detector.py`
- **Test Count Update**: Expanded from 112 to 124 total tests
  - Test breakdown: 10 parser + 62 detector (14 scoring + 50 technique detection) + 25 decoder + 1 integration + 26 benign
  - All 124 tests passing (100% pass rate)
- **Documentation**: Updated `tests/README.md` to document new test structure and coverage
- **Phase 1 vs Phase 2**:
  - **Phase 1 (Complete)**: 5 techniques (T1059, T1218, T1027, T1105, T1071) with 86 tests
  - **Phase 2 (Current)**: 7 techniques (added T1543, T1055) with 124 tests, 180+ detection patterns

### Documentation Updates
- **README.md**: Updated technique coverage list, test count (112 → 124), pattern count (166+ → 180+)
- **Phase 2 Status**: Marked T1543 and T1055 as complete (✅), updated roadmap status
- **Sample Commands**: Extended with 10 new realistic malicious command examples
- **tests/README.md**: Added `detect_t1543()` and `detect_t1055()` test documentation, updated test counts

### Roadmap Progress
- **Phase 1**: ✅ Complete (5 techniques, 86 tests)
- **Phase 2**: 🔄 Current (7 techniques, 124 tests, T1543/T1055 complete, process relationship analysis in progress)
- **Phase 3**: 💭 Planned (Advanced enrichment, technique chaining, ML-enhanced scoring)
- **Phase 4**: 🔮 Future (SIEM/Sigma integration, real-time API)

Date: 2026-03-01

## Benign Command False-Positive Testing
- **Test Suite Addition**: Created comprehensive benign/legitimate command test coverage (`tests/test_benign_commands.py`)
  - 26 new test cases covering realistic Windows/Linux administration workflows
  - Zero high-confidence false positives on benign commands (excellent baseline!)
  - Categories tested: Windows administration, network operations, DevOps automation, scripting, logging, file operations
- **False-Positive Analysis Tool**: Implemented `test_benign_commands_false_positive_rate()` summary test
  - Aggregates false-positive detections across benign command set
  - Calculates false-positive rate and confidence metrics
  - Provides analyst-friendly summary for pattern refinement
  - Assertion: ≤20% of benign commands trigger medium+ confidence detections
- **Testing Categories**:
  - Windows system administration (7 tests): Update checks, process enumeration, disk space, services, firewall, scheduled tasks
  - Legitimate network operations (5 tests): ping, DNS, curl/wget utility flags, localhost health checks
  - DevOps & automation (4 tests): Docker, Git, npm, pip package management
  - Legitimate scripting (3 tests): WScript basic usage, PowerShell modules, batch execution
  - Logging & monitoring (3 tests): Event log parsing, log searching, tail -f operations
  - File operations & backups (4 tests): robocopy, compression, file copies
- **Documentation**:
  - Added dedicated "Benign Command False-Positive Testing" section in README.md
  - Explains trade-off philosophy: acceptable false positives vs. malware detection sensitivity
  - Provides guidance on understanding and responding to false-positive detections
  - Trade-off metrics: 0.45-confidence noise is acceptable; 0.85-confidence is worth investigating
- **Test Results**: All 26 benign tests pass (0 high-confidence false positives)
- **Total Test Count Update**: Expanded from 86 to 112 tests (86 unit/integration + 26 benign)

## Pytest Integration & Test Infrastructure Modernization
- **Testing Framework Migration**: Transitioned from custom manual test runners to industry-standard pytest (v9.0.2+)
  - Removed manual test runner blocks (`if __name__ == "__main__"` boilerplate) from all 4 original test files
  - Reduces maintenance burden (~150 lines of boilerplate code removed)
  - Enables modern testing workflows and CI/CD integration
- **All Tests Passing**: 112 total tests (85 original unit + 1 integration + 26 benign) all pass with pytest
  - 10 parser tests: Command normalization
  - 75 detector tests: Confidence scoring (14) + T1059/T1218/T1027/T1105/T1071 detection (61)
  - 25 decoder tests: Encoding detection and multi-layer decoding
  - 1 integration test: Realistic attack chains with 100% detection accuracy
- **Documentation Updates**:
  - `tests/README.md`: Comprehensive pytest usage guide with filtering, targeting, and advanced options
  - `docs/test_implementation_summary.md`: Updated design decisions to reflect pytest adoption
  - `README.md`: Removed manual test runner references, updated to pytest-only commands
  - Root `README.md`: Test count updated to 86 total (100% pass rate)
- **Pytest Capabilities Documented**:
  - Basic execution: `pytest tests/`
  - Specific files: `pytest tests/test_detector.py`
  - Single functions: `pytest tests/test_detector.py::test_score_confidence_zero_evidence`
  - Pattern filtering: `pytest tests/test_detector.py -k "t1105 or t1071"`
  - Advanced options: `-x`, `-l`, `--tb=short`, `--tb=long`, `--failed-first`, `-q`, `-s`
  - Watch mode: `pytest-watch` integration documented
- **Zero Breaking Changes**: All test logic preserved, only execution method modernized

Date: 2026-02-26

## T1105 & T1071 Detection (Network-Based Techniques)
- **T1105 (Ingress Tool Transfer)**: Added comprehensive detection for file/tool transfer patterns:
  - PowerShell: `DownloadFile()`, `DownloadString()`, `Invoke-WebRequest()`, `Invoke-RestMethod()`
  - LOLBins: `certutil -urlcache`, `bitsadmin /transfer`, `curl`, `wget`, `tftp`, `ftp -s:`
  - ActiveX: `XMLHTTP`, `ActiveXObject('XMLHTTP')`, `WinHttp.WinHttpRequest`, `ServerXMLHTTP`
  - Network utilities: `scp`, `rsync`
  - **Total**: 16 critical patterns added to `technique_pattern_db.py`
- **T1071 (Application Layer Protocol)**: Added detection for suspicious network communication:
  - HTTP/HTTPS URLs in command lines
  - Network objects: `WebClient`, `XMLHTTP`, `WinHttp.WinHttpRequest`
  - PowerShell cmdlets: `Invoke-WebRequest`, `Invoke-RestMethod`
  - Suspicious indicators: TLDs (`.tk`, `.ml`, `.xyz`), direct IP addresses, non-standard ports
  - **Total**: 10 critical patterns added to `technique_pattern_db.py`
- **Detector Functions**: Added `detect_t1105()` and `detect_t1071()` in `src/core/detector.py`
- **Metadata Enrichment**: Added 16 metadata entries for T1105/T1071 patterns with:
  - Detailed attacker intent and behavior descriptions
  - SOC investigation notes and detection opportunities
  - Telemetry sources (Sysmon Event IDs, PowerShell logs, network logs)
  - Launcher/interpreter context
- **Detection Accuracy**: 100% detection rate on realistic commands (5/5 each)
- **Integration**: Both techniques available via `--include-secondary-techniques` flag
- **Realistic Command Testing**: Updated `test_realistic_commands.py` to validate T1105/T1071 detection on network-based attacks
- **Flowchart Update**: Updated `docs/odt_application_flowchart.mmd` to include T1105 and T1071 detection flow

Date: 2026-02-25

## Secondary Technique Detection Testing (T1218 & T1027)
- **T1218 Unit Tests**: Added 8 comprehensive tests for System Binary Proxy Execution:
  - mshta proxy execution detection (basic and advanced)
  - ActiveX object usage patterns  
  - rundll32 detection
  - Evidence extraction and confidence scoring
  - No false positives on benign commands
  - Output structure validation
  - Network-related proxy patterns
  - Multiple pattern detection scenarios
- **T1027 Unit Tests**: Added 7 comprehensive tests for Obfuscated Files or Information:
  - T1027.002 (Software packing tools: upx, themida, mpress, aspack)
  - T1027.003 (Steganography: steghide, Invoke-PSImage)
  - String concatenation obfuscation patterns
  - No false positives
  - Evidence extraction and structure validation
  - Confidence scoring with evidence
- **Test Count Update**: Expanded from 59 to 74 unit tests
- **Realistic Integration Tests**: Added 10 end-to-end integration tests using realistic "analyst headache" commands from `sample_commands.md`:
  - Multi-technique attack chains (PowerShell → mshta → JavaScript → ActiveX)
  - Various obfuscation levels (light, heavy, extreme)
  - Remote code download and execution
  - Multi-layer staging attacks
  - **Detection Performance**: 100% accuracy (T1059: 10/10, T1218: 8/8, T1027: 7/7)
- **Documentation Updates**: 
  - Updated `tests/README.md` with comprehensive test coverage details
  - Updated root `README.md` to reflect 84 total tests (74 unit + 10 integration)
  - Added realistic test execution instructions

Date: 2026-02-24 (continued)

## CLI Enhancements
- **Short Flag for Decode**: Added `-d` as short option for `--decode` flag (previously only `--decode` was available)

## Expanded Unit Testing
- **detect_t1059() Tests**: Added 10 comprehensive tests for T1059 detection function:
  - T1059.007 JavaScript detection (mshta context)
  - T1059.005 VBScript detection (mshta context)
  - Detection in suspicious command contexts
  - Evidence extraction and accumulation
  - Confidence scoring progression
  - Output structure validation
  - Pattern suppression logic verification
  - No false positives on benign commands
- **Total Test Count**: Expanded from 49 to 59 tests
- **test_detector.py**: Now tests both `score_confidence()` (14 tests) and `detect_t1059()` (10 tests)

## Obfuscation Handling & Unit Testing
- **Decoder Module**: Created `src/core/decoder.py` to detect and decode common obfuscation techniques:
  - PowerShell base64 (`-encodedCommand`)
  - JavaScript atob() base64 encoding
  - JavaScript/VBScript String.fromCharCode() / chr() char code arrays
  - URL encoding (%XX)
  - Unicode escapes (\uXXXX)
  - Hex encoding (0xXX)
- **Hybrid Approach**: Decoder detects obfuscation patterns (for T1027 mapping) and optionally decodes (for improved T1059 detection)
- **CLI Integration**: Added `--decode` flag to enable optional decoding before detection
- **Pipeline Integration**: Integrated decoder into `pipeline.py` with `decode_info` output when decoding occurs
- **Sample Commands**: Added 5 heavily obfuscated sample commands to `sample_commands.md` for testing
- **Comprehensive Unit Tests**: Created 49 unit tests across 3 test files:
  - `tests/test_parser.py` (10 tests): command normalization, whitespace handling, edge cases
  - `tests/test_detector.py` (14 tests): confidence scoring, evidence-based adjustments, bonuses/penalties
  - `tests/test_decoder.py` (25 tests): encoding detection, individual decoders, multi-layer decoding
- **Test Infrastructure**: Added simple built-in test runner with no dependencies, clear pass/fail output
- **Documentation**: Created `tests/README.md` with usage guide and test coverage details
- **README Update**: Added "Development & Testing" section to main README with test running instructions

Date: 2026-02-24

## Pattern Coverage Improvements & Output Enhancements
- **New T1059 Patterns**: Added `mshta_javascript_execution` and `mshta_vbscript_execution` to cover T1059.007 and T1059.005 via mshta script protocols
- **Indirect Command Execution**: Added `wscript_shell_run_cmd_indirect` and `mshta_wscript_shell_run_cmd` patterns to detect cmd.exe execution via WScript.Shell.Run()
- **Evidence Extraction**: Fixed T1218.001 evidence extraction to capture ActiveXObject, XMLHTTP, and WScript.Shell references with higher confidence scoring
- **Enriched T1218 Metadata**: Created 5 new metadata entries with detailed attacker intent, telemetry sources, and detection opportunities
- **CLI Output Flag**: Added `-o/--output` flag to save results to `data/results/` with automatic timestamp (format: `filename_YYYYMMDD_HHMMSS.json`)
- **Gitignore Cleanup**: Reorganized .gitignore with better categorization and added `data/results/` to prevent accidental commits

## Detection Quality Improvements
- T1218.005 (mshta) now detects with confidence 0.63 (basic detection)
- T1218.001 (script protocol + ActiveX) now detects with confidence 0.88 (enriched)
- T1059.007 (JavaScript execution) now detects with confidence 0.88 (pattern match + keywords)
- T1059.003 (cmd.exe indirect execution) now detects with multiple variants:
  - Generic WScript.Shell.Run pattern: confidence 0.82
  - Specific mshta context: confidence 0.88

Date: 2026-02-14

## Multi-Technique Expansion
- **Secondary technique coverage**: `--include-secondary-techniques` now adds all non-primary techniques present in the rule set (currently T1218 and T1027, and any future additions).
- **Unified detection flow**: Refactored detectors to share a generic technique pipeline with technique-specific hooks (scope filtering, evidence handling, mshta suppression).
- **Sub-technique naming**: T1027 and T1218 now emit sub-technique IDs/names when available.

## MITRE Cache Improvements
- **Unified cache**: Replaced the T1059-only cache with a single cache that includes all techniques/sub-techniques.
- **Lazy warm-up**: Cache is warmed only when secondary techniques are requested.
- **Legacy migration**: Existing T1059 cache is migrated into the unified cache format.

Date: 2026-02-13

## Confidence Scoring Update
- **Evidence-driven confidence**: Replaced the hardcoded per-pattern `base_confidence` with a computed `confidence` score derived from evidence size and diversity.
- **Metadata cleanup**: Removed all `base_confidence` entries from `metadata.py` to keep confidence logic centralized.
- **Default prior**: Introduced a fixed baseline prior (0.5) used by the scoring function when no prior is provided.

## Major Enhancements: Enriched Detection Output with MITRE Tactics and Defensive Insights

### Core Infrastructure
- **Tactic Extraction from MITRE**: Extended `mitre.py` with `_extract_tactic()` function to parse `kill_chain_phases` from MITRE ATT&CK data
  - Added `_build_technique_index()` to support querying any technique ID (T1059, T1218, T1027, etc.)
  - Added `get_technique_tactic()` to retrieve tactics for any technique
  
### Detection System Enrichment
- **Enhanced Detector Output**: Updated all three detection functions (`detect_t1059()`, `detect_t1218()`, `detect_t1027()`) to include:
  - `tactic`: MITRE ATT&CK tactic (e.g., "Execution", "Defense Evasion")
  - `attacker_intent`: Pattern-specific strategic intent from metadata (domain knowledge)
  - `defensive_enrichment`: Complete defensive context with telemetry, detection opportunities, and SOC notes

### Metadata Enrichment at Scale
- **Pattern Metadata Enhancement**: Expanded `metadata.py` structure for all 166+ entries with:
  - `attacker_intent`: Why this pattern is dangerous from an attacker perspective (currently sparse to highlight gaps)
  - `defensive_enrichment.telemetry_sources`: Where to find evidence (Sysmon, logs, etc.)
    - PowerShell patterns: Sysmon Event ID 1, PowerShell operational logs (+ Event ID 3 for network)
    - JavaScript/VBScript: Sysmon Event ID 1, WMI Event Logs (+ Event ID 3 for network)
    - Command Shell: Sysmon Event ID 1, Windows Command Line Audit logs
    - AppleScript: osascript audit logs (+ Event ID 3 for network)
    - Python: Python process logs (+ Event ID 3 for network)
    - Unix Shell: Bash audit logs, Linux process accounting
    - Network Device: Network device audit logs
  - `defensive_enrichment.detection_opportunities`: Specific indicators to monitor
  - `defensive_enrichment.soc_notes`: Context and recommendations for analysts

### Output Format Transformation
- **Structured SOC-Ready Output** (`output.py`):
  - Implemented `_enrich_detections()` function to transform raw detections
  - New output structure with three main sections:
    - `mitre_mapping`: Tactic, technique name, IDs (T1059, T1059.007, etc.)
    - `analysis`: Behavior, attacker_intent, confidence, evidence
    - `defensive_enrichment`: Telemetry sources, detection opportunities, SOC notes
  - Provides intelligent defaults for entries without custom enrichment

### Technical Implementation
- File modifications:
  - `src/odt/core/mitre.py`: +40 lines for tactic extraction
  - `src/odt/core/detector.py`: Updated imports and all detection functions for enriched output
  - `src/odt/core/output.py`: Refactored for new enriched structure
  - `src/odt/detection/metadata.py`: 166 entries enriched with telemetry and defensive data

---

Date: 2026-02-05

## Updates
- Added `--include-secondary-techniques` flag to keep T1059-only output by default while allowing extra technique context on demand.
- Added T1218.005 (mshta) proxy execution detection alongside T1059 detections.
- Preserved inline JavaScript attribution for mshta while suppressing duplicate mshta JS signals.
- Added WScript.Shell.Run -> cmd.exe detection for secondary shell hops.
- Expanded cmd interpreter chaining to include mshta and updated evidence handling.
- Added WScript.Shell.Run -> PowerShell detection for indirect PowerShell execution.
- Added T1027 detection for JavaScript string concatenation obfuscation.

---

Date: 2026-02-04

## Goal
A minimal, T1059-only translator pipeline was added to reduce complexity and make the project easier to build upon. MITRE technique and subtechnique names are now fetched via the attackcti library and cached locally for offline reuse.

## High-Level Outcomes
- Introduced a minimal “core” pipeline focused only on T1059.
- Added a MITRE data adapter using attackcti with local caching in data/mitre.
- Added a simple CLI for single-command analysis.
- Preserved the existing rule patterns and metadata, but narrowed their usage to T1059 in the minimal pipeline.
- Added requirements.txt with attackcti pinned for install convenience.
- Removed legacy tests and docs not aligned with the minimal pipeline.

## New Files Added
- src/odt/core/__init__.py
  - Exposes translate_command for easy import from odt.core.
- src/odt/core/parser.py
  - normalize_command(): trims and collapses whitespace.
- src/odt/core/mitre.py
  - attackcti adapter that:
    - fetches techniques + subtechniques from MITRE TAXII
    - builds a T1059-only index
    - caches output at data/mitre/attackcti_t1059.json
    - provides get_technique_name() and get_subtechnique_name()
- src/odt/core/detector.py
  - detect_t1059(): runs T1059-only regex matching and enriches results with MITRE names and metadata.
- src/odt/core/output.py
  - build_output(): returns standardized JSON structure.
- requirements.txt
  - Adds attackcti>=0.6.4 for MITRE data access.

## Updated Files
- src/odt/pipeline.py
  - Now re-exports translate_command from the new core pipeline.
- src/odt/cli/main.py
  - Added CLI entrypoint with:
    - command argument or stdin input
    - --refresh-mitre flag to force cache refresh
    - JSON output
- src/odt/__init__.py
  - Re-exports translate_command at package root for convenience.

## Removed Items
- tests/ (all prior test files)
- docs/architecture.md
- docs/enrichment_logic.md
- docs/examples.md
- docs/mitre_mapping.md
- docs/Command and Scripting Interpreter, Technique T1059 - Enterprise _ MITRE ATT&CK®.pdf

## Minimal Pipeline Data Flow
1) normalize_command()
2) detect_t1059()
3) build_output()

Output schema:
{
  "input_command": <raw input>,
  "normalized_command": <whitespace-normalized>,
  "detections": [
    {
      "technique_id": "T1059",
      "technique": <MITRE name>,
      "subtechnique_id": "T1059.xxx",
      "subtechnique": <MITRE name>,
      "behavior": <metadata behavior>,
      "confidence": <metadata base confidence>,
      "evidence": [<matched indicators>]
    }
  ]
}

## MITRE Data Source Details
- attackcti is used as the authoritative MITRE ATT&CK source.
- Caching avoids repeated TAXII calls and allows offline use.
- Cache path:
  - data/mitre/attackcti_t1059.json

## Notes on Compatibility
- All new code uses Python 3.6-compatible typing (no | unions).

## Next Options (If You Want)
- Remove or relocate non-core modules to a “legacy” directory to reduce visual clutter.
- Add tests for the minimal pipeline.
- Expand the core pipeline beyond T1059 by adding additional technique filters.
- Extend the output with defensive enrichment once the minimal translator is stable.
