RULES = [
            # FIXME: The "execution" for some fields is probably wrong
            # List of T1059 sub-technique IDs with associated regex patterns 
            # Design a few GENERAL patterns for spotting powershell suspicious code execution using command patterns for technique T1059.001:
        {
            "id": "ps_downloadstring",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*\(New-Object\s+Net\.WebClient\)\.(DownloadString|DownloadData)\(", # DownloadString or DownloadData method
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_reflection_assembly_load",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*\[Reflection\.Assembly\]::Load\(", # Reflection Assembly Load
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_add_type_typedefinition",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Add-Type\s+-TypeDefinition", # Add-Type with TypeDefinition
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_encoded_command",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]n(codedCommand)?\s+[A-Za-z0-9+/=]{20,}", # EncodedCommand with base64 string
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]x(ecute)?\s+\$[a-zA-Z0-9_]+\s*=\s*(iwr|Invoke-WebRequest|wget|curl|irm)\s+http[s]?://", # Execute with variable assignment from web request
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://", # Web request commands
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://.*\|\s*(iex|Invoke-Expression)", # Web request piped to expression
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm).*\|\s*(iex|Invoke-Expression)", # Any web request piped to expression
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*New-Object\s+Net\.WebClient.*DownloadString\s*\(", # New-Object WebClient DownloadString
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Net\.WebClient.*DownloadFile\s*\(", # WebClient DownloadFile
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*System\.Net\.WebRequest.*GetResponse\s*\(", # WebRequest GetResponse
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Add-Type\s+.*DllImport", # Add-Type with DllImport
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Reflection\.Assembly::Load", # Reflection Assembly Load
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*FromBase64String\s*\(", # FromBase64String method
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Invoke-Command\s+-ScriptBlock", # Invoke-Command with ScriptBlock
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Start-Process\s+.*-ArgumentList", # Start-Process with ArgumentList
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-ExecutionPolicy\s+Bypass", # ExecutionPolicy Bypass
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-NoProfile", # NoProfile flag
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },
        {
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-WindowStyle\s+Hidden", # Hidden WindowStyle
            "technique": "T1059",
            "sub_technique": ".001",
            "execution": "powershell"
        },

        
            # Design a few GENERAL patterns for spotting Apple Script suspicious code execution using command patterns for technique T1059.002:
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*http[s]?://", # AppleScript downloading from URL
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*http[s]?://", # AppleScript do shell script with URL
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*curl\s+-O\s+http[s]?://", # AppleScript curl download
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*wget\s+http[s]?://", # AppleScript wget download
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*base64\s+-D\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*bash", # AppleScript base64 decode piped to bash
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },

            # Other high-confidence variants
        {
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".002",
            "execution": "osascript"
        },

            # Design a few GENERAL patterns for spotting Windows Command Shell suspicious code execution using command patterns for technique T1059.003:
        {
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+powershell\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+wmic\s+process\s+call\s+create\s+", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+start\s+.*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+ftp\s+-s:", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+regsvr32\s+/s\s+/n\s+/u\s+/i:http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+mshta\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+rundll32\s+url.dll,FileProtocolHandler\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://", # certutil download from URL
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://", # bitsadmin transfer command
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", # powershell encoded command
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+wmic\s+process\s+call\s+create\s+", # wmic process create
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+start\s+.*http[s]?://.*\.(exe|dll|js|vbs|hta|ps1|bat|cmd)", # start command with URL
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+ftp\s+-s:", # ftp script execution
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+regsvr32\s+/s\s+/n\s+/u\s+/i:http[s]?://", # regsvr32 with URL
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+mshta\s+http[s]?://", # mshta with URL
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+rundll32\s+url\.dll,FileProtocolHandler\s+http[s]?://",  # rundll32 with URL
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", # certutil download and execute
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", # bitsadmin download and execute
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+(powershell|pwsh|cmd|wscript|cscript)\.exe", # Shell-to-shell pivot (critical)
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+schtasks\s+/create", # Scheduled task creation (optional but strong)
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },
        {
            "pattern": r"cmd\.exe\s+/c\s+at\s+", # Legacy scheduled task creation (optional but strong)
            "technique": "T1059",
            "sub_technique": ".003",
            "execution": "cmd"
        },


            # Design a few GENERAL patterns for spotting Unix Shell suspicious code execution using command patterns for technique T1059.004:
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+curl\s+-O\s+http[s]?://", # Unix shell curl download
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+wget\s+http[s]?://", # Unix shell wget download
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+base64\s+-d\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*bash", # Base64 decode piped to bash
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d\s*\|\s*bash", # Echo base64 decode piped to bash
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+perl\s+-e\s+['\"][^'\"]*http[s]?://", # Perl one-liner downloading from URL
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+python\s+-c\s+['\"][^'\"]*http[s]?://", # Python one-liner downloading from URL
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
        {
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+curl\s+-O\s+http[s]?://.*\s+&&\s+(\S+)", # curl download and execute
            "technique": "T1059",
            "sub_technique": ".004",
            "execution": "shell"
        },
            # Design a few GENERAL patterns for spotting Visual Basic suspicious code execution using command patterns for technique T1059.005:
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*\.vbs\s+", # VBScript execution
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:mshta)(?:\.exe)?\s+http[s]?://.*\.vbs\s*", # mshta executing VBScript from URL
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*\.vbs\s*,\s*.*", # rundll32 executing VBScript
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", # Encoded VBScript
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*CreateObject\s*\(\s*\"Scripting\.FileSystemObject\"\s*\)", # CreateObject FileSystemObject
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Execute\s*\(", # Execute function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Run\s*\(", # Run function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*FromBase64String\s*\(", # FromBase64String method
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },
        {
            "pattern": r"(?:mshta)(?:\.exe)?\s+.*Execute\s*\(", # mshta Execute function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Execute\s*\(", # rundll32 Execute function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Run\s*\(", # rundll32 Run function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*FromBase64String\s*\(", # rundll32 FromBase64String method
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Eval\s*\(", # rundll32 Eval function
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": "shell"
        },

            # Other high-confidence variants
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.vbs)", # Encoded VBScript decode and execute
            "technique": "T1059",
            "sub_technique": ".005",
            "execution": ["vbs", "vbscript", "wscript", "cscript"]
        },


            # Design a few GENERAL patterns for spotting Python suspicious code execution using command patterns for technique T1059.006:
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*-c\s+['\"]import\s+urllib\.request;?\s*urllib\.request\.urlopen\(['\"]http[s]?://", # Python one-liner downloading from URL
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://", # Python script using requests to download from URL
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)", # Python executing base64 decoded string
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*os\.system\s*\(\s*['\"]curl\s+-O\s+http[s]?://", # Python os.system with curl download
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*subprocess\.Popen\s*\(\s*['\"]wget\s+http[s]?://", # Python subprocess with wget download
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"]python\s+-c\s+['\"]import\s+urllib\.request;?\s*urllib\.request\.urlopen\(['\"]http[s]?://", # Nested Python download via os.system
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },

            # Other high-confidence variants
        {
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*-c\s+['\"]import\s+urllib\.request;?\s*response\s*=\s*urllib\.request\.urlopen\(['\"]http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".006",
            "execution": ["python", "python3", "py"]
        },

            # Design a few GENERAL patterns for spotting JavaScript suspicious code execution using command patterns for technique T1059.007:
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*\.js\s+", # JScript execution
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:mshta)(?:\.exe)?\s+http[s]?://.*\.js\s*", # mshta executing JScript from URL
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*\.js\s*,\s*.*", # rundll32 executing JScript
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", # Encoded JScript
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*CreateObject\s*\(\s*\"MSScriptControl\.ScriptControl\"\s*\)", # CreateObject ScriptControl
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Eval\s*\(", # Eval function
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Execute\s*\(", # Execute function
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Run\s*\(", # Run function
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*FromBase64String\s*\(", # FromBase64String method
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:mshta)(?:\.exe)?\s+.*Eval\s*\(", # mshta Eval function
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Eval\s*\(", # rundll32 Eval function
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.js)", # Encoded JScript decode and execute
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+javascript:", # mshta with javascript
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\brundll32\.exe\b\s+javascript:", # rundll32 with javascript
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+https?:\/\/[^\s]+\.hta\b",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+.*\\(users|temp|appdata|downloads|public)\\[^\s]+\.hta\b",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+javascript:",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+vbscript:",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+about:",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)<hta:application>",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+https?:\/\/[^\s]+\.(html?|php|asp|jsp)\b",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b.*(activexobject|xmlhttp|adodb\.stream)",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b.*(eval\(|atob\(|chr\(|execute\()",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)(cmd\.exe|powershell\.exe|wscript\.exe|rundll32\.exe).*\bmshta\.exe\b",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },
        {
            "pattern": r"(?i)\bmshta\.exe\b\s+.+",
            "technique": "T1059",
            "sub_technique": ".007",
            "execution": "jscript"
        },

            # TODO Define the remaining T1059.008-010 subtechniques

            # Design a few GENERAL patterns for spotting Lua suspicious code execution using command patterns for technique T1059.011:
         {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*-e\s+['\"][^'\"]*http[s]?://", # Lua one-liner downloading from URL
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]
        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*loadstring\s*\(.*http[s]?://", # loadstring with URL
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*require\s*\(\s*['\"]socket['\"]\s*\).*http[s]?://", # require socket with URL
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*os\.execute\s*\(\s*['\"]curl\s+-O\s+http[s]?://", # os.execute with curl download
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*os\.execute\s*\(\s*['\"]wget\s+http[s]?://", # os.execute with wget download
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*base64\.decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)\s*\|\s*loadstring", # Base64 decode piped to loadstring
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*base64\.decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)\s*\|\s*loadfile", # Base64 decode piped to loadfile
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*io\.popen\s*\(\s*['\"]curl\s+-O\s+http[s]?://", # io.popen with curl download
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*io\.popen\s*\(\s*['\"]wget\s+http[s]?://", # io.popen with wget download
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
        {
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".011",
            "execution": ["lua", "luajit"]

        },
            # Design a few GENERAL patterns for spotting Hypervisor CLI. Adversaries may abuse hypervisor command line interpreters (CLIs) to execute malicious commands.
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://", # Hypervisor CLI downloading from URL
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://", # Hypervisor CLI using requests to download from URL
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)", # Hypervisor CLI executing base64 decoded string
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*system\s*\(\s*['\"]curl\s+-O\s+http[s]?://", # Hypervisor CLI system with curl download
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*subprocess\s*\(\s*['\"]wget\s+http[s]?://", # Hypervisor CLI subprocess with wget download
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"](virsh|VBoxManage|qm|xe|govc)\s+-c\s+['\"][^'\"]*http[s]?://", # Nested Hypervisor CLI download via os.system
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        # Design a few GENERAL patterns for spotting Container CLI/API. Adversaries may abuse built-in CLI tools or API calls to execute malicious commands in containerized environments.
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://", # Container CLI downloading from URL
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://", # Container CLI using requests to download from URL
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)", # Container CLI executing base64 decoded string
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*system\s*\(\s*['\"]curl\s+-O\s+http[s]?://", # Container CLI system with curl download
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*subprocess\s*\(\s*['\"]wget\s+http[s]?://", # Container CLI subprocess with wget download
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"](docker|kubectl|podman|crictl)\s+-c\s+['\"][^'\"]*http[s]?://", # Nested Container CLI download via os.system
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        },
        {
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".012",
            "execution": "shell"
        }
    ]