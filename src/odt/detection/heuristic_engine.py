import re
import odt.detection.interpreter_markers as interpreter_markers
import odt.detection.metadata as metadata

from src.odt.detection.technique_pattern_db import RULES

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

    # Determine if the command is executed via PowerShell or CMD
    # Then check for patterns accordingly
    # Finally, return the result dictionary containing the technique and sub-technique IDs if matched

    # Define auxiliary functions to help detect the sub-technique ID
    cmd_lower = command.lower()
    is_powershell = any(x in cmd_lower for x in ("powershell", "pwsh"))
    is_cmd = "cmd.exe" in cmd_lower
    is_osascript = "osascript" in cmd_lower
    # Define for Linux shell
    is_shell = any(x in cmd_lower for x in ("/bin/sh", "/bin/bash", "bash", "sh"))
    # Define for Lua
    is_lua = any(x in cmd_lower for x in ("lua", "luajit"))

    # TODO Implement for other interpreters
    # Define for Python
    is_python = any(x in cmd_lower for x in ("python", "python3", "py"))
    # Define for JavaScript (Node.js)
    is_javascript = any(x in cmd_lower for x in ("node", "nodejs", "node.exe"))
    # Define for Visual Basic (cscript/wscript)
    is_vbscript = any(x in cmd_lower for x in ("cscript", "wscript", "vbs", "vbscript"))


    # TODO The loop structure enforces "first match wins"
    # You will want multiple findings, not one verdict
    # This loop checks each pattern for the given technique ID
    findings = []
    for rule in RULES.items():

            if re.search(rule["pattern"], command, re.IGNORECASE):
                if rule["execution"] == "powershell" and is_powershell:
                    matched = [
                        x for x in interpreter_markers.POWERSHELL_001_INDICATORS if x in cmd_lower
                    ]

                    if matched:
                        findings.append({
                            "technique_id": rule["technique"],
                            "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                            "behaviors": [
                                {
                                    "behavior": "Encoded PowerShell execution",
                                    "evidence": [],
                                    "confidence": None
                                }
                            ]
                        })

                elif rule["execution"] == "shell" and is_cmd:
                    matched = [
                        x in cmd_lower for x in interpreter_markers.CMD_003_INDICATORS if x in cmd_lower
                        ]
                    if matched:
                        findings.append({
                            "technique_id": rule["technique"],
                            "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                            "behaviors": [
                                {
                                    "behavior": "CMD execution via common utilities",
                                    "evidence": [],
                                    "confidence": None
                                }
                            ],
                            "evidence": [],
                        })

                
                elif rule["execution"] == "osascript":
                    if "osascript" in cmd_lower and is_osascript:
                        findings.append({
                            "technique_id": rule["technique"],
                            "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                            "behaviors": [
                                {
                                    "behavior": "AppleScript execution",
                                    "evidence": [],
                                    "confidence": None
                                }
                            ],
                            "evidence": [],
                        })
                
                elif rule["execution"] == "shell" and is_shell:
                    matched = [
                        x for x in interpreter_markers.UNIX_SHELL_004_INDICATORS if x in cmd_lower
                    ]

                    if matched:
                        findings.append({
                            "technique_id": rule["technique"],
                            "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                            "behaviors": [
                                {
                                    "behavior": "Unix Shell execution via common utilities",
                                    "evidence": [],
                                    "confidence": None
                                }
                            ]
                        })
                
                elif "lua" in rule["execution"] or "luajit" in rule["execution"]:
                    if is_lua:
                        
                        matched = [
                            x for x in interpreter_markers.LUA_011_INDICATORS if x in cmd_lower
                        ]
                        if matched:
                            findings.append({
                                "technique_id": rule["technique"],
                                "sub_technique_id": f'{rule["technique"]}{rule["sub_technique"]}',
                                "behaviors": [
                                    {
                                        "behavior": "Lua script execution",
                                        "evidence": [],
                                        "confidence": None
                                    }
                                ]
                            })

                # Implement logic for other interpreters as needed, e.g., Unix Shell, Python, JavaScript, etc.
                # ...

            return findings
    return findings
