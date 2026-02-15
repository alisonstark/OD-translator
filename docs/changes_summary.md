# Changes Summary (Multi-technique Pipeline + attackcti)

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
