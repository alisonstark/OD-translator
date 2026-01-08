import re
import src.odt.detection.indicators as indicators

from src.odt.detection.technique_identifier import HEURISTIC_PATTERNS

# Analyze command strings against heuristic patterns
def analyze(
        command: str,
) -> dict:
    """
    Analyzes a command string to determine if it matches known patterns
    associated with a specific technique ID.

    Args:
        command (str): The command string to analyze.
        technique_id (str): The technique ID to check against. Default is "T1059".

    Returns:
        dict: A dictionary containing the analysis result.
    """

    # Determine if the command is executed via PowerShell or CMD
    # Then check for patterns accordingly
    # Finally, return the result dictionary containing the technique and sub-technique IDs if matched

    cmd_lower = command.lower()
    is_powershell = any(x in cmd_lower for x in ("powershell", "pwsh"))
    is_cmd = "cmd.exe" in cmd_lower


    # This loop checks each pattern for the given technique ID
    for technique_id, patterns in HEURISTIC_PATTERNS.items():
        for pattern in patterns:

            if not re.search(pattern, command, re.IGNORECASE):
                continue

            sub_technique = None

            if is_powershell:
                if any(indicator in cmd_lower for indicator in indicators.POWERSHELL_001_INDICATORS):
                    sub_technique = ".001"

            elif is_cmd:
                if any(indicator in cmd_lower for indicator in indicators.CMD_003_INDICATORS):
                    sub_technique = ".003"

            return {
                "technique_id": technique_id,
                "sub_technique_id": technique_id + sub_technique if sub_technique else None,
                "matched_pattern": pattern,
                "command": command,
                "result": "match"
            }

    return {
        "technique_id": None,
        "sub_technique_id": None,
        "matched_pattern": None,
        "command": command,
        "result": "no match"
    }
