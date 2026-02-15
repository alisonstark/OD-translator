import re
from typing import Any, Dict, List, Set

from core.mitre import (
    get_subtechnique_name,
    get_subtechnique_name_for,
    get_technique_name,
    get_technique_name_for,
    get_technique_tactic,
)
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

    return round(max(0.0, min(1.0, score)), 2)


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


def _get_default_technique_name(technique_id: str, refresh_mitre: bool = False) -> str:
    mitre_name = get_technique_name_for(technique_id, refresh=refresh_mitre)
    if mitre_name:
        return mitre_name
    if technique_id == "T1059":
        return "Command and Scripting Interpreter"
    if technique_id == "T1027":
        return "Obfuscated Files or Information"
    if technique_id == "T1218":
        return "System Binary Proxy Execution"
    return technique_id


def _build_subtechnique_id(technique_id: str, sub_id: str) -> str:
    normalized = (sub_id or "").lstrip(".")
    return f"{technique_id}.{normalized}" if normalized else technique_id

# The following functions implement the detection logic for specific MITRE ATT&CK techniques (T1059, T1218, T1027) 
# based on predefined rules and patterns.
# Each function analyzes the input command against relevant rules, extracts evidence, 
# and constructs a list of findings with associated technique information, behavior descriptions, confidence scores, 
# and evidence indicators.
def _detect_technique_generic(
    command: str,
    technique_id: str,
    refresh_mitre: bool = False,
    rule_filter: Any = None,
    evidence_builder: Any = None,
    subtechnique_name_builder: Any = None,
    technique_name_override: str | None = None,
    tactic_override: str | None = None,
    postprocess: Any = None,
) -> List[Dict[str, object]]:
    command_lower = command.lower()
    findings: List[Dict[str, object]] = []
    candidates: List[Dict[str, object]] = []
    matched_rule_ids: Set[str] = set()

    technique_name = technique_name_override or _get_default_technique_name(
        technique_id,
        refresh_mitre=refresh_mitre,
    )
    tactic_default = "Execution" if technique_id == "T1059" else "Defense Evasion"
    tactic = tactic_override or get_technique_tactic(technique_id, refresh=refresh_mitre) or tactic_default

    for rule in RULES:
        if rule.get("technique") != technique_id:
            continue

        if not re.search(rule.get("pattern", ""), command, re.IGNORECASE):
            continue

        rule_id = rule.get("id")
        metadata = PATTERN_METADATA.get(rule_id, {})

        if rule_filter and not rule_filter(rule, metadata, command_lower):
            continue

        if evidence_builder:
            evidence = evidence_builder(rule, metadata, command_lower)
            if evidence is None:
                continue
        else:
            indicators = metadata.get("indicators", [])
            evidence = _match_indicators(command_lower, indicators)
            if indicators and not evidence:
                continue

        sub_id = (rule.get("sub_technique") or "").lstrip(".")
        subtechnique_id = _build_subtechnique_id(technique_id, sub_id)
        if subtechnique_name_builder:
            subtechnique_name = subtechnique_name_builder(sub_id, refresh_mitre)
        else:
            subtechnique_name = get_subtechnique_name_for(technique_id, sub_id, refresh=refresh_mitre)
        if not subtechnique_name:
            subtechnique_name = subtechnique_id if sub_id else technique_name

        candidates.append(
            {
                "rule_id": rule_id,
                "technique_id": technique_id,
                "technique": technique_name,
                "subtechnique_id": subtechnique_id,
                "subtechnique": subtechnique_name,
                "tactic": tactic,
                "behavior": metadata.get("behavior", "Suspicious behavior"),
                "attacker_intent": metadata.get("attacker_intent", "Likely malicious activity"),
                "confidence": score_confidence(DEFAULT_BASE_CONFIDENCE, evidence),
                "evidence": evidence,
                "defensive_enrichment": metadata.get("defensive_enrichment", {}),
            }
        )
        matched_rule_ids.add(rule_id)

    if postprocess:
        candidates = postprocess(candidates, matched_rule_ids)

    for candidate in candidates:
        candidate.pop("rule_id", None)
        findings.append(candidate)

    return findings


def detect_t1059(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    command_lower = command.lower()
    primary_scope = _detect_primary_scope(command_lower)

    mshta_js_suppress = {
        "mshta_activeX",
        "mshta_eval",
        "mshta_js_eval",
        "mshta_js_execution",
        "mshta_chain_command",
        "mshta_command",
    }

    def rule_filter(rule: Dict[str, Any], metadata: Dict[str, Any], _: str) -> bool:
        rule_id = rule.get("id", "")
        rule_scope = metadata.get("rule_scope", "")
        if primary_scope and rule_scope and rule_scope != primary_scope:
            if not rule_id.startswith("mshta_"):
                return False
        return True

    def evidence_builder(rule: Dict[str, Any], metadata: Dict[str, Any], command_lower: str) -> List[str] | None:
        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            return None
        return evidence

    def postprocess(candidates: List[Dict[str, object]], matched_rule_ids: Set[str]) -> List[Dict[str, object]]:
        if "mshta_javascript" in matched_rule_ids:
            return [
                candidate
                for candidate in candidates
                if candidate.get("rule_id") not in mshta_js_suppress
            ]
        return candidates

    return _detect_technique_generic(
        command,
        "T1059",
        refresh_mitre=refresh_mitre,
        rule_filter=rule_filter,
        evidence_builder=evidence_builder,
        postprocess=postprocess,
    )


def detect_t1218(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    def evidence_builder(rule: Dict[str, Any], metadata: Dict[str, Any], command_lower: str) -> List[str] | None:
        rule_id = rule.get("id")
        if rule_id == "mshta_proxy":
            return ["mshta.exe"] if "mshta.exe" in command_lower else ["mshta"]
        indicators = metadata.get("indicators", [])
        evidence = _match_indicators(command_lower, indicators)
        if indicators and not evidence:
            return None
        return evidence

    def subtechnique_name_builder(sub_id: str, refresh_mitre: bool) -> str:
        mitre_name = get_subtechnique_name_for("T1218", sub_id, refresh=refresh_mitre)
        if mitre_name:
            return mitre_name
        return _build_t1218_names(sub_id).get("subtechnique", f"T1218.{sub_id}")

    return _detect_technique_generic(
        command,
        "T1218",
        refresh_mitre=refresh_mitre,
        evidence_builder=evidence_builder,
        subtechnique_name_builder=subtechnique_name_builder,
    )


def detect_t1027(command: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    return _detect_technique_generic(
        command,
        "T1027",
        refresh_mitre=refresh_mitre,
    )


def detect_technique(command: str, technique_id: str, refresh_mitre: bool = False) -> List[Dict[str, object]]:
    if technique_id == "T1059":
        return detect_t1059(command, refresh_mitre=refresh_mitre)
    if technique_id == "T1218":
        return detect_t1218(command, refresh_mitre=refresh_mitre)
    if technique_id == "T1027":
        return detect_t1027(command, refresh_mitre=refresh_mitre)

    return _detect_technique_generic(
        command,
        technique_id,
        refresh_mitre=refresh_mitre,
    )


def detect_secondary_techniques(
    command: str,
    primary_technique: str = "T1059",
    refresh_mitre: bool = False,
) -> List[Dict[str, object]]:
    technique_ids: List[str] = []
    seen: Set[str] = set()
    for rule in RULES:
        technique_id = rule.get("technique")
        if not technique_id or technique_id == primary_technique:
            continue
        if technique_id in seen:
            continue
        seen.add(technique_id)
        technique_ids.append(technique_id)

    findings: List[Dict[str, object]] = []
    for technique_id in technique_ids:
        findings.extend(detect_technique(command, technique_id, refresh_mitre=refresh_mitre))

    return findings
