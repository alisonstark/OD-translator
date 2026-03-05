from core.output import build_output


def test_generic_intent_is_confidence_aware_at_50_percent() -> None:
    detections = [
        {
            "tactic": "Defense Evasion",
            "technique": "T1055",
            "technique_id": "T1055",
            "subtechnique": "T1055.001",
            "subtechnique_id": "T1055.001",
            "behavior": "Suspicious behavior",
            "attacker_intent": "Likely malicious activity",
            "confidence": 0.5,
            "evidence": [],
            "defensive_enrichment": {},
        }
    ]

    output = build_output("cmd", "cmd", detections)
    intent = output["detections"][0]["analysis"]["attacker_intent"]
    assert intent == "Suspicious activity requiring further investigation"


def test_specific_metadata_intent_is_preserved() -> None:
    detections = [
        {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "subtechnique": "PowerShell",
            "subtechnique_id": "T1059.001",
            "behavior": "PowerShell Reflection Assembly Load",
            "attacker_intent": "Download and execute remote code in memory",
            "confidence": 0.5,
            "evidence": ["Reflection.Assembly"],
            "defensive_enrichment": {},
        }
    ]

    output = build_output("cmd", "cmd", detections)
    intent = output["detections"][0]["analysis"]["attacker_intent"]
    assert intent == "Download and execute remote code in memory"
