PATTERN_METADATA = {

    # -------------------------
    # PowerShell
    # -------------------------
    "ps_encoded_command": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "Encoded PowerShell execution",
        "indicators": ["-enc", "base64"], # What evidence in the command supports this behavior?
        "base_confidence": 0.9,
    },

    "ps_reflection_assembly_load": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Reflection Assembly Load",
        "indicators": ["Reflection.Assembly", "Load"], # What evidence in the command supports this behavior?
        "base_confidence": 0.8,
    },

    # TODO Continue adding more PowerShell behaviors here (from technique_pattern_db.py)


    "ps_downloadstring": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell download cradle",
        "indicators": ["DownloadString", "WebClient"], # What evidence in the command supports this behavior?
        "base_confidence": 0.85,
    },

    # -------------------------
    # CMD
    # -------------------------
    "cmd_mshta_chain": {
        "launcher": "cmd",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command shell spawning script proxy",
        "indicators": ["mshta", "lolbin"],
        "base_confidence": 0.75,
    },

    # -------------------------
    # Unix Shell
    # -------------------------
    "unix_shell_curl": {
        "launcher": "bash",
        "interpreter": "unix_shell",
        "rule_scope": "shell",
        "behavior": "Unix shell downloading remote payload",
        "indicators": ["curl", "download"],
        "base_confidence": 0.7,
    },

    # -------------------------
    # VBScript
    # -------------------------
    "mshta_vbscript_exec": {
        "launcher": "mshta",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript execution via mshta",
        "indicators": ["Execute", "scripting"],
        "base_confidence": 0.8,
    },

    # -------------------------
    # Python
    # -------------------------
    "python_urlopen": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python remote resource access",
        "indicators": ["urlopen", "network"],
        "base_confidence": 0.75,
    },

    # -------------------------
    # JavaScript
    # -------------------------
    "wscript_js": {
        "launcher": "wscript",
        "interpreter": "jscript",
        "rule_scope": "javascript",
        "behavior": "JScript execution via Windows Script Host",
        "indicators": ["wscript", ".js"],
        "base_confidence": 0.8,
    },
    "rundll32_js_eval": {
        "launcher": "rundll32",
        "interpreter": "jscript",
        "rule_scope": "javascript",
        "behavior": "JavaScript execution via rundll32",
        "indicators": ["Eval", "proxy_execution"],
        "base_confidence": 0.85,
    },
    "mshta_about_js": {
        "launcher": "mshta",
        "interpreter": "jscript",
        "rule_scope": "javascript",
        "behavior": "JavaScript execution via mshta about: handler",
        "indicators": ["about:", "mshta"],
        "base_confidence": 0.85,
    },

    # -------------------------
    # Lua
    # -------------------------
    "lua_inline_exec": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua inline execution with remote content",
        "indicators": ["-e", "http"],
        "base_confidence": 0.7,
    },
}
