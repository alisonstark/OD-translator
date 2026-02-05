import re
from typing import Dict, List

from odt.core.mitre import get_subtechnique_name, get_technique_name
from odt.detection.metadata import PATTERN_METADATA
from odt.detection.technique_pattern_db import RULES


def _match_indicators(command_lower: str, indicators: List[str]) -> List[str]:
    return [indicator for indicator in indicators if indicator.lower() in command_lower]


def detect_t1059(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    command_lower = command.lower()
    technique_name = get_technique_name(refresh=refresh_mitre) or "Command and Scripting Interpreter"
    findings: List[Dict[str, object]] = []

    for rule in RULES:
        if rule.get("technique") != "T1059":
            continue

        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        metadata = PATTERN_METADATA.get(rule_id, {})

        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            continue

        sub_id = (rule.get("sub_technique") or "").lstrip(".")
        subtechnique_id = f"T1059.{sub_id}" if sub_id else "T1059"
        subtechnique_name = get_subtechnique_name(sub_id, refresh=refresh_mitre) or subtechnique_id

        findings.append(
            {
                "technique_id": "T1059",
                "technique": technique_name,
                "subtechnique_id": subtechnique_id,
                "subtechnique": subtechnique_name,
                "behavior": metadata.get("behavior", "Suspicious command pattern"),
                "confidence": metadata.get("base_confidence", 0.5),
                "evidence": evidence,
            }
        )

    return findings
