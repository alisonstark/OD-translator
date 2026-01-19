import re
import odt.detection.interpreter_markers as interpreter_markers
import odt.detection.metadata as metadata # To be used in future for behavior metadata
import odt.detection.technique_identifier as technique_identifier

from src.odt.detection.technique_pattern_db import RULES

# Helper function to extract evidence based on indicators
def extract_evidence(indicator_map: dict, command_lower: str) -> dict:
    evidence = {}

    for capability, indicators in indicator_map.items():
        hits = [i for i in indicators if i in command_lower]
        if hits:
            evidence[capability] = hits

    return evidence


# Analyze command strings against heuristic patterns
def analyze(
        command: str
) -> list[dict]:
    """
    Analyzes a command string to determine if it matches known patterns
    associated with a specific technique ID.

    Args:
        command (str): The command string to analyze.
        technique_id (str): The technique ID to check against. Default is "T1059".

    Returns:
        List of ... 
        {
            "technique_id": "T1059",
            "sub_technique_id": "T1059.001",
            "behaviors": [
                {
                    "behavior": "Encoded PowerShell execution",
                    "evidence": ["-enc", "FromBase64String"],
                    "confidence": 0.9
                }
            ]
        }

    """
    

    # This loop checks each pattern for the given technique ID
    findings = []

    cmd_lower = command.lower()
    for rule in RULES:
        if re.search(rule["pattern"], command, re.IGNORECASE):
            rule_id = rule["id"]

            # Determine command context flags
            interpreter = metadata.PATTERN_METADATA[rule_id]["interpreter"]
            

            # Context flags for specific interpreters
            indicator_key = interpreter_markers.INTERPRETER_KEY_MAP.get(interpreter, None)
            indicator_map = interpreter_markers.INTERPRETER_INDICATORS.get(indicator_key)
            if not indicator_map:
                continue  # No indicators defined for this interpreter

            evidence = extract_evidence(indicator_map, cmd_lower)
            if not evidence:
                continue  # No relevant indicators found, skip to next rule

            # Where would I use the indicators key of the metadata?
            # indicators = metadata.PATTERN_METADATA[rule_id].get("indicators", []) are indicators of malicious behavior?
            # If needed, could cross-check indicators here # TODO Investigate further
            
            # Build finding entry
            confidence = metadata.PATTERN_METADATA[rule_id].get("base_confidence", None)
            behavior = metadata.PATTERN_METADATA[rule_id]["behavior"]
            technique_name = technique_identifier.check_technique_name(rule["technique"], rule["sub_technique"])
            findings.append({
                "name": technique_name,
                "technique_id": rule["technique"],
                "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                "behaviors": [
                    {
                        "behavior": behavior,
                        "evidence": evidence,
                        "confidence": confidence
                        # How to use metadata.PATTERN_METADATA[rule_id].get("indicators", []) here?
                        
                    }
                ]
            })

    return findings
