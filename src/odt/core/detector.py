import re
from typing import Dict, List, Set

from odt.core.mitre import get_subtechnique_name, get_technique_name
from odt.detection.metadata import PATTERN_METADATA
from odt.detection.technique_pattern_db import RULES


def _match_indicators(command_lower: str, indicators: List[str]) -> List[str]:
    return [indicator for indicator in indicators if indicator.lower() in command_lower]


def _detect_primary_scope(command_lower: str) -> str:
    if re.search(r"^\s*cmd(?:\.exe)?\s+/c\b", command_lower):
        return "cmd"
    return ""


def _build_t1218_names(sub_id: str) -> Dict[str, str]:
    if sub_id == "005":
        return {
            "technique": "System Binary Proxy Execution",
            "subtechnique": "Mshta",
        }
    return {
        "technique": "System Binary Proxy Execution",
        "subtechnique": f"T1218.{sub_id}",
    }


def detect_t1059(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    command_lower = command.lower()
    primary_scope = _detect_primary_scope(command_lower)
    technique_name = get_technique_name(refresh=refresh_mitre) or "Command and Scripting Interpreter"
    findings: List[Dict[str, object]] = []
    candidates: List[Dict[str, object]] = []
    matched_rule_ids: Set[str] = set()

    mshta_js_suppress = {
        "mshta_activeX",
        "mshta_eval",
        "mshta_js_eval",
        "mshta_js_execution",
        "mshta_chain_command",
        "mshta_command",
    }

    for rule in RULES:
        if rule.get("technique") != "T1059":
            continue

        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        metadata = PATTERN_METADATA.get(rule_id, {})

        rule_scope = metadata.get("rule_scope", "")
        if primary_scope and rule_scope and rule_scope != primary_scope:
            if not rule_id.startswith("mshta_"):
                continue

        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            continue

        sub_id = (rule.get("sub_technique") or "").lstrip(".")
        subtechnique_id = f"T1059.{sub_id}" if sub_id else "T1059"
        subtechnique_name = get_subtechnique_name(sub_id, refresh=refresh_mitre) or subtechnique_id

        candidates.append(
            {
                "rule_id": rule_id,
                "technique_id": "T1059",
                "technique": technique_name,
                "subtechnique_id": subtechnique_id,
                "subtechnique": subtechnique_name,
                "behavior": metadata.get("behavior", "Suspicious command pattern"),
                "confidence": metadata.get("base_confidence", 0.5),
                "evidence": evidence,
            }
        )
        matched_rule_ids.add(rule_id)

    if "mshta_javascript" in matched_rule_ids:
        candidates = [
            candidate
            for candidate in candidates
            if candidate.get("rule_id") not in mshta_js_suppress
        ]

    for candidate in candidates:
        candidate.pop("rule_id", None)
        findings.append(candidate)

    return findings


def detect_t1218(command: str) -> List[Dict[str, object]]:
    command_lower = command.lower()
    findings: List[Dict[str, object]] = []

    for rule in RULES:
        if rule.get("technique") != "T1218":
            continue

        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        metadata = PATTERN_METADATA.get(rule_id, {})

        if rule_id == "t1218_mshta_proxy":
            evidence = ["mshta.exe"] if "mshta.exe" in command_lower else ["mshta"]
        else:
            indicators = metadata.get("indicators", [])
            evidence = _match_indicators(command_lower, indicators)
            if indicators and not evidence:
                continue

        sub_id = (rule.get("sub_technique") or "").lstrip(".")
        subtechnique_id = f"T1218.{sub_id}" if sub_id else "T1218"
        names = _build_t1218_names(sub_id)

        findings.append(
            {
                "technique_id": "T1218",
                "technique": names["technique"],
                "subtechnique_id": subtechnique_id,
                "subtechnique": names["subtechnique"],
                "behavior": metadata.get("behavior", "Suspicious proxy execution"),
                "confidence": metadata.get("base_confidence", 0.5),
                "evidence": evidence,
            }
        )

    return findings


def detect_t1027(command: str) -> List[Dict[str, object]]:
    command_lower = command.lower()
    findings: List[Dict[str, object]] = []

    for rule in RULES:
        if rule.get("technique") != "T1027":
            continue

        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        metadata = PATTERN_METADATA.get(rule_id, {})

        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            continue

        findings.append(
            {
                "technique_id": "T1027",
                "technique": "Obfuscated Files or Information",
                "subtechnique_id": "T1027",
                "subtechnique": "Obfuscated Files or Information",
                "behavior": metadata.get("behavior", "Obfuscated content"),
                "confidence": metadata.get("base_confidence", 0.5),
                "evidence": evidence,
            }
        )

    return findings
