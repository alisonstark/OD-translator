# TODO: Learn the Codebase (Suggested Path)

## 1) Trace the pipeline end‑to‑end
- Run a simple command through `translate_command()` and log each stage output.
- Step through `normalize_command()` to see whitespace changes.
- Step through `detect_t1059()` to see which rules match and why.
- Inspect the final shape produced by `build_output()`.

## 2) Map rule → metadata → output
- Pick one command that matches multiple rules (e.g., an `mshta.exe` JavaScript example).
- For each matched rule ID in `technique_pattern_db`, locate its entry in `metadata`.
- Note how `indicators` affect filtering and how `base_confidence` carries through.

## 3) Understand heuristic logic
- Read `heuristic_engine.analyze()` and compare with `detect_t1059()`.
- Write down the differences (e.g., indicator maps, interpreter markers, evidence structure).
- Decide which path is “primary” for your use cases.

## 4) Add 2–3 sample commands
- Add two known‑bad and one benign‑ish command to a scratch list.
- Predict which rules should match before running.
- Run them and compare expected vs actual detections.

## 5) Add minimal tests (safety net)
- Create tests for:
  - `normalize_command()` (whitespace collapse)
  - `detect_t1059()` (at least one known rule hit)
- Keep tests small and focused so refactoring is safe.

## 6) Create a tiny “debug harness” (optional)
- Write a short script that prints:
  - original command
  - normalized command
  - matched rule IDs
  - final output JSON
- Use this as your quick‑feedback tool while you study.

## 7) Document your findings
- Keep notes on any confusing rules or mismatches.
- Mark areas where metadata or patterns feel too broad.
- Convert those into future TODOs or improvements.
