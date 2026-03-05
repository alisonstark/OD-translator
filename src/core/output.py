def format_detections_with_separator(detections: list, separator: str = "\n----\n") -> str:
    """
    Format a list of detection dicts into a readable string with a separator between findings.
    """
    formatted = []
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    for idx, detection in enumerate(detections, 1):
        # Highlight Finding number in yellow
        lines = [f"{YELLOW}Finding {idx}:{RESET}"]
        mitre = detection.get("mitre_mapping", {})
        analysis = detection.get("analysis", {})
        enrichment = detection.get("defensive_enrichment", {})
        lines.append(f"  MITRE Tactic: {mitre.get('tactic', 'Unknown')}")
        lines.append(f"  Technique: {mitre.get('technique', 'Unknown')} ({mitre.get('technique_id', 'Unknown')})")
        if mitre.get('subtechnique_id') and mitre.get('subtechnique_id') != mitre.get('technique_id'):
            lines.append(f"  Subtechnique: {mitre.get('subtechnique', '')} ({mitre.get('subtechnique_id', '')})")
        lines.append(f"  Behavior: {analysis.get('behavior', 'N/A')}")
        lines.append(f"  Attacker Intent: {analysis.get('attacker_intent', 'N/A')}")
        lines.append(f"  Confidence: {analysis.get('confidence', 'N/A')}")
        evidence = analysis.get('evidence', [])
        if evidence:
            lines.append("  Evidence:")
            for ev in evidence:
                lines.append(f"    - {ev}")
        if enrichment:
            lines.append("  Defensive Enrichment:")
            for k, v in enrichment.items():
                if isinstance(v, list):
                    lines.append(f"    {k}:")
                    for item in v:
                        lines.append(f"      - {item}")
                else:
                    lines.append(f"    {k}: {v}")
        formatted.append("\n".join(lines))
    return separator.join(formatted)
from typing import Any, Dict, List

# This module defines the output structure for the ODT (Offense Detection Translator) system, 
# which takes the original command, the normalized command, and the detections from various techniques
# to build a structured output that can be used for reporting or further analysis.

# This function is a helper to remove duplicate evidence items from the list, 
# ensuring that the output is concise and does not contain redundant information.
# There's a check for duplicates using a set to track seen items, and only unique items are added to the deduped list.
# But this function serves as a safeguard to ensure that the evidence list in the final output does not contain redundant entries,
# even if the detection logic might already be designed to avoid duplicates. It's a final step to ensure clean output.
def _dedupe_evidence(evidence: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for item in evidence:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _normalize_attacker_intent(attacker_intent: str, confidence: float) -> str:
    """Adjust generic attacker intent wording so it aligns with confidence level."""
    intent = (attacker_intent or "").strip()
    lowered = intent.lower()

    # Only remap generic fallback wording. Keep specific metadata intent intact.
    generic_intents = {
        "likely malicious activity",
        "suspicious activity requiring investigation",
        "execute code via interpreter or proxy",
    }
    if lowered not in generic_intents:
        return intent

    if confidence >= 0.75:
        return "Highly suspicious activity with strong malicious indicators"
    if confidence >= 0.60:
        return "Likely malicious activity"
    if confidence >= 0.40:
        return "Suspicious activity requiring further investigation"
    return "Low-confidence suspicious signal; corroborate with additional telemetry"

# This module defines the output structure for the ODT (Offense Detection Translator) system, 
# which takes the original command, the normalized command, and the detections from various techniques 
# to build a structured output that can be used for reporting or further analysis.
def build_output(
    original_command: str,
    normalized_command: str,
    detections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build enriched output with MITRE mapping, analysis, and defensive enrichment.
    Takes detections and transforms them into a structured format suitable for SOC reports.
    """
    
    return {
        "input_command": original_command,
        "normalized_command": normalized_command,
        "detections": _enrich_detections(detections),
    }


def _enrich_detections(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Transform raw detection results into enriched format with MITRE mapping, analysis, and recommendations."""
    enriched = []
    
    for detection in detections:
        enriched_detection = {
            "mitre_mapping": {
                "tactic": detection.get("tactic", "Unknown"),
                "technique": detection.get("technique", "Unknown"),
                "technique_id": detection.get("technique_id", "Unknown"),
                "subtechnique": detection.get("subtechnique", detection.get("technique_id")),
                "subtechnique_id": detection.get("subtechnique_id", detection.get("technique_id")),
            },
            "analysis": {
                "behavior": detection.get("behavior", "Suspicious activity detected"),
                "attacker_intent": _normalize_attacker_intent(
                    detection.get("attacker_intent", "Suspicious activity requiring investigation"),
                    float(detection.get("confidence", 0.5)),
                ),
                "confidence": detection.get("confidence", 0.5),
                "evidence": _dedupe_evidence(detection.get("evidence", [])),
            },
        }
        
        # Add defensive enrichment if available
        defensive_enrichment = detection.get("defensive_enrichment", {})
        if defensive_enrichment:
            enriched_detection["defensive_enrichment"] = defensive_enrichment
        else:
            # Default defensive enrichment if not provided
            enriched_detection["defensive_enrichment"] = {
                "telemetry_sources": ["Process execution logs"],
                "detection_opportunities": ["Monitor for unusual process patterns"],
                "soc_notes": "Further investigation recommended"
            }
        
        enriched.append(enriched_detection)
        
    
    return enriched
