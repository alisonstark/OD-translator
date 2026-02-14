import re
from typing import Any, Dict, List, Set

from core.mitre import get_subtechnique_name, get_technique_name, get_technique_tactic
from detection.metadata import PATTERN_METADATA
from detection.technique_pattern_db import RULES

# Default base confidence score for detections, which can be adjusted based on the presence and quality 
# of evidence indicators.
DEFAULT_BASE_CONFIDENCE = 0.5

_GENERIC_EVIDENCE = {
    "http",
    "https",
    "-e",
    "/c",
    "cmd",
    "bash",
    "powershell",
    "wscript",
    "cscript",
    "python",
    "mshta",
}

_CHAIN_TOKENS = {"&&", "||", "|", ";"}

# Helper functions for evidence categorization and confidence scoring, which analyze the matched indicators 
# to determine the strength of the detection and adjust the confidence score accordingly. 

# The categorization helps identify the types of evidence present (e.g., download behavior, obfuscation, chaining) 
# and the scoring function combines these factors to produce a final confidence score for the detection.
def _categorize_evidence(indicator: str) -> str:
    indicator_lower = indicator.lower()
    if re.search(r"http|https|curl|wget|bitsadmin|certutil|invoke-webrequest|webrequest", indicator_lower):
        return "download"
    if re.search(r"base64|encoded|frombase64", indicator_lower):
        return "obfuscation"
    if indicator_lower in _CHAIN_TOKENS or re.search(r"&&|\|\||\||;", indicator_lower):
        return "chaining"
    if re.search(r"cmd|powershell|bash|python|wscript|cscript|mshta|rundll32", indicator_lower):
        return "interpreter"
    return "other"

# The confidence scoring function evaluates the quantity and diversity of evidence indicators, 
# the presence of specific categories of evidence (e.g., chaining, download behavior), 
# and the ratio of generic indicators to adjust the confidence score for the detection. 
# This allows for a more nuanced assessment of the detection's reliability, 
# where stronger and more varied evidence leads to a higher confidence score, 
# while a high ratio of generic indicators may reduce confidence due to the increased likelihood of false positives.
def score_confidence(base_confidence: float, evidence: List[str]) -> float:
    evidence = [item for item in evidence if item]
    evidence_count = len(evidence)
    categories = {_categorize_evidence(item) for item in evidence}
    diversity = len(categories)

    has_chain = 1 if "chaining" in categories else 0
    has_download = 1 if "download" in categories else 0

    generic_hits = sum(1 for item in evidence if item.lower() in _GENERIC_EVIDENCE)
    generic_ratio = (generic_hits / evidence_count) if evidence_count else 0.0
    generic_penalty = 1 if generic_ratio >= 0.6 else 0

    score = (
        base_confidence
        + 0.06 * min(evidence_count, 4)
        + 0.07 * min(diversity, 3)
        + 0.05 * has_chain
        + 0.05 * has_download
        - 0.04 * generic_penalty
    )

    return max(0.0, min(1.0, score))


def _match_indicators(command_lower: str, indicators: List[str]) -> List[str]:
    seen = set()
    matches = []
    for indicator in indicators:
        if indicator.lower() not in command_lower:
            continue
        if indicator in seen:
            continue
        seen.add(indicator)
        matches.append(indicator)
    return matches

# Helper functions for specific detection logic, such as determining primary scope for rule filtering 
# and building technique names for T1218 sub-techniques.
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

# The following functions implement the detection logic for specific MITRE ATT&CK techniques (T1059, T1218, T1027) 
# based on predefined rules and patterns.
# Each function analyzes the input command against relevant rules, extracts evidence, 
# and constructs a list of findings with associated technique information, behavior descriptions, confidence scores, 
# and evidence indicators.
def detect_t1059(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    command_lower = command.lower()

    # Determine primary scope for rule filtering (e.g., cmd.exe /c) to reduce false positives, especially for mshta rules
    primary_scope = _detect_primary_scope(command_lower)
    technique_name = get_technique_name(refresh=refresh_mitre) or "Command and Scripting Interpreter"
    findings: List[Dict[str, object]] = []
    candidates: List[Dict[str, object]] = []
    matched_rule_ids: Set[str] = set()

    # Suppress certain mshta-related rules if a JavaScript execution pattern is detected to avoid false positives,
    # since mshta can be used for both command execution and JavaScript execution, 
    # and the latter may not always indicate T1059 activity.
    mshta_js_suppress = {
        "mshta_activeX",
        "mshta_eval",
        "mshta_js_eval",
        "mshta_js_execution",
        "mshta_chain_command",
        "mshta_command",
    }

    # Iterate through T1059 rules and apply filtering logic based on primary scope and evidence indicators.
    for rule in RULES:
        # Only consider rules explicitly associated with T1059 to maintain focus on the primary technique,
        # while secondary techniques (T1027, T1218) are handled separately if the include_secondary_techniques flag is set.
        if rule.get("technique") != "T1059":
            continue
        
        # Use case-insensitive regex search to check if the command matches the rule's pattern,
        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        # Retrieve metadata for the matched rule to access indicators, behavior descriptions, and confidence scores.
        metadata = PATTERN_METADATA.get(rule_id, {})

        # Filter rules based on primary scope to reduce false positives, 
        # especially for mshta rules which can be used in various contexts.
        rule_scope = metadata.get("rule_scope", "")
        # If the rule has a defined scope and it doesn't match the primary scope of the command, skip it.
        if primary_scope and rule_scope and rule_scope != primary_scope:
            if not rule_id.startswith("mshta_"):
                continue
        
        # Check for required indicators in the command to validate the rule match, 
        # and if indicators are defined but not found in the command, skip the rule.
        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            continue

        sub_id = (rule.get("sub_technique") or "").lstrip(".")
        subtechnique_id = f"T1059.{sub_id}" if sub_id else "T1059"
        subtechnique_name = get_subtechnique_name(sub_id, refresh=refresh_mitre) or subtechnique_id
        tactic = get_technique_tactic("T1059", refresh=refresh_mitre) or "Execution"

        candidates.append(
            {
                "rule_id": rule_id,
                "technique_id": "T1059",
                "technique": technique_name,
                "subtechnique_id": subtechnique_id,
                "subtechnique": subtechnique_name,
                "tactic": tactic,
                "behavior": metadata.get("behavior", "Suspicious command pattern"),
                "attacker_intent": metadata.get("attacker_intent", "Execute suspicious code via interpreter"),
                "confidence": score_confidence(DEFAULT_BASE_CONFIDENCE, evidence),
                "evidence": evidence,
                "defensive_enrichment": metadata.get("defensive_enrichment", {}),
            }
        )
        matched_rule_ids.add(rule_id)

    # If any mshta-related rules are matched and the command contains patterns indicative of JavaScript execution,
    # suppress certain mshta rules that are more likely to indicate JavaScript execution rather than command execution 
    # to reduce false positives in T1059 detection, since mshta can be used for both purposes.
    if "mshta_javascript" in matched_rule_ids:
        candidates = [
            candidate
            for candidate in candidates
            if candidate.get("rule_id") not in mshta_js_suppress
        ]
    # Remove rule_id from candidates before adding to findings to clean up the output, 
    # as rule_id is only used for internal processing and is not relevant to the final output structure.
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
        tactic = get_technique_tactic("T1218") or "Defense Evasion"

        findings.append(
            {
                "technique_id": "T1218",
                "technique": names["technique"],
                "subtechnique_id": subtechnique_id,
                "subtechnique": names["subtechnique"],
                "tactic": tactic,
                "behavior": metadata.get("behavior", "Suspicious proxy execution"),
                "attacker_intent": metadata.get("attacker_intent", "Execute code via signed binary proxy"),
                "confidence": score_confidence(DEFAULT_BASE_CONFIDENCE, evidence),
                "evidence": evidence,
                "defensive_enrichment": metadata.get("defensive_enrichment", {}),
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

        tactic = get_technique_tactic("T1027") or "Defense Evasion"

        findings.append(
            {
                "technique_id": "T1027",
                "technique": "Obfuscated Files or Information",
                "subtechnique_id": "T1027",
                "subtechnique": "Obfuscated Files or Information",
                "tactic": tactic,
                "behavior": metadata.get("behavior", "Obfuscated content"),
                "attacker_intent": metadata.get("attacker_intent", "Hide malicious code from detection"),
                "confidence": score_confidence(DEFAULT_BASE_CONFIDENCE, evidence),
                "evidence": evidence,
                "defensive_enrichment": metadata.get("defensive_enrichment", {}),
            }
        )

    return findings
