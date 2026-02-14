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
                "attacker_intent": detection.get("attacker_intent", "Execute code via interpreter or proxy"),
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
