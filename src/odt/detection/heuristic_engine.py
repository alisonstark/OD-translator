import re
import src.odt.detection.indicators as indicators

from src.odt.detection.technique_pattern_db import HEURISTIC_PATTERNS

# Analyze command strings against heuristic patterns
def analyze(
        command: str
) -> dict:
    """
    Analyzes a command string to determine if it matches known patterns
    associated with a specific technique ID.

    Args:
        command (str): The command string to analyze.
        technique_id (str): The technique ID to check against. Default is "T1059".

    Returns:
        dict (Example): 
            [
                {
                "tactic": "Execution",
                "technique_id": "T1059.007",
                "technique_name": "Command and Scripting Interpreter: JavaScript"
                },

                {
                "tactic": "Defense Evasion",
                "technique_id": "T1218.011",
                "technique_name": "Signed Binary Proxy Execution: Rundll32"
                }
            ]
    """

    # Determine if the command is executed via PowerShell or CMD
    # Then check for patterns accordingly
    # Finally, return the result dictionary containing the technique and sub-technique IDs if matched

    # Define auxiliary functions to help detect the sub-technique ID
    cmd_lower = command.lower()
    is_powershell = any(x in cmd_lower for x in ("powershell", "pwsh"))
    is_cmd = "cmd.exe" in cmd_lower


    # This loop checks each pattern for the given technique ID
    for technique_id, patterns in HEURISTIC_PATTERNS.items():
        for pattern in patterns:

            if not re.search(pattern, command, re.IGNORECASE):
                continue
            
            

            return {
                # TODO Include: Technique name --> Import from technique_identifier.py module
                "technique_id": technique_id.split('.')[0],
                "sub_technique_id": technique_id,   # Keep
                "command": command,                 # Required for "input_command": str
            }

    return {
        "technique_name": None,
        "technique_id": None,
        "sub_technique_id": None,
        "command": command,
    }
