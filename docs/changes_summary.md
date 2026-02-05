# Changes Summary (T1059 Minimal Pipeline + attackcti)

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
