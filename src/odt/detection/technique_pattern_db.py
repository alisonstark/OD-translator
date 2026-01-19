RULES = [
            # --------------------------------------------------------------
            # List of T1059 sub-technique IDs with associated regex patterns 
            # --------------------------------------------------------------


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
            "id": "ps_web_request_execute",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]x(ecute)?\s+\$[a-zA-Z0-9_]+\s*=\s*(iwr|Invoke-WebRequest|wget|curl|irm)\s+http[s]?://", # Execute with variable assignment from web request
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_web_request",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://", # Web request commands
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_web_request_direct_url_piped_iex",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://.*\|\s*(iex|Invoke-Expression)", # Web request piped to expression
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_web_request_generic_piped_iex",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm).*\|\s*(iex|Invoke-Expression)", # Any web request piped to expression
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_downloadstring_newobject",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*New-Object\s+Net\.WebClient.*DownloadString\s*\(", # New-Object WebClient DownloadString
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_downloadfile",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Net\.WebClient.*DownloadFile\s*\(", # WebClient DownloadFile
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_webrequest_getresponse",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*System\.Net\.WebRequest.*GetResponse\s*\(", # WebRequest GetResponse
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_add_type_dllimport",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Add-Type\s+.*DllImport", # Add-Type with DllImport
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_frombase64string",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*FromBase64String\s*\(", # FromBase64String method
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_invoke_command_scriptblock",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Invoke-Command\s+-ScriptBlock", # Invoke-Command with ScriptBlock
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_start_process_argumentlist",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*Start-Process\s+.*-ArgumentList", # Start-Process with ArgumentList
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_executionpolicy_bypass",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-ExecutionPolicy\s+Bypass", # ExecutionPolicy Bypass
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_noprofile",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-NoProfile", # NoProfile flag
            "technique": "T1059",
            "sub_technique": ".001"
        },
        {
            "id": "ps_hidden_windowstyle",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*-WindowStyle\s+Hidden", # Hidden WindowStyle
            "technique": "T1059",
            "sub_technique": ".001"
        },

        
        # Design a few GENERAL patterns for spotting Apple Script suspicious code execution using command patterns for technique T1059.002:
        {
            "id": "as_download_from_url",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*http[s]?://", # AppleScript downloading from URL
            "technique": "T1059",
            "sub_technique": ".002"
        },
        {
            "id": "as_do_shell_script_with_url",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*http[s]?://", # AppleScript do shell script with URL
            "technique": "T1059",
            "sub_technique": ".002"
        },
        {
            "id": "as_curl_download",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*curl\s+-O\s+http[s]?://", # AppleScript curl download
            "technique": "T1059",
            "sub_technique": ".002"
        },
        {
            "id": "as_wget_download",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*wget\s+http[s]?://", # AppleScript wget download
            "technique": "T1059",
            "sub_technique": ".002"
        },
        {
            "id": "as_base64_decode_to_bash",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*do shell script ['\"][^'\"]*base64\s+-D\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*bash", # AppleScript base64 decode piped to bash
            "technique": "T1059",
            "sub_technique": ".002"
        },
        {
            "id": "as_download_and_execute",
            "pattern": r"osascript\s+-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)", # Download and execute
            "technique": "T1059",
            "sub_technique": ".002"
        },

        # Design a few GENERAL patterns for spotting Windows Command Shell suspicious code execution using command patterns for technique T1059.003:
        {
            "id": "cmd_certutil_urlcache_split",
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_bitsadmin_transfer",
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_powershell_encoded_command",
            "pattern": r"cmd\.exe\s+/c\s+powershell\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_wmic_process_call_create",
            "pattern": r"cmd\.exe\s+/c\s+wmic\s+process\s+call\s+create\s+", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_start_http_url",
            "pattern": r"cmd\.exe\s+/c\s+start\s+.*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_ftp_script",
            "pattern": r"cmd\.exe\s+/c\s+ftp\s+-s:", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_regsvr32_http_url",
            "pattern": r"cmd\.exe\s+/c\s+regsvr32\s+/s\s+/n\s+/u\s+/i:http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_mshta_http_url",
            "pattern": r"cmd\.exe\s+/c\s+mshta\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_rundll32_url_handler",
            "pattern": r"cmd\.exe\s+/c\s+rundll32\s+url.dll,FileProtocolHandler\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_certutil_urlcache_split_f",
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_bitsadmin_transfer_s",
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_powershell_encoded_command_s",
            "pattern": r"cmd\.exe\s+/c\s+powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_start_http_url_executable",
            "pattern": r"cmd\.exe\s+/c\s+start\s+.*http[s]?://.*\.(exe|dll|js|vbs|hta|ps1|bat|cmd)", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_rundll32_url_handler_escaped",
            "pattern": r"cmd\.exe\s+/c\s+rundll32\s+url\.dll,FileProtocolHandler\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_certutil_urlcache_split_f_chain",
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_bitsadmin_transfer_f",
            "pattern": r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_execute_command",
            "pattern": r"cmd\.exe\s+/c\s+(powershell|pwsh|cmd|wscript|cscript)\.exe", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_schtasks_create",
            "pattern": r"cmd\.exe\s+/c\s+schtasks\s+/create", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "cmd_at_command",
            "pattern": r"cmd\.exe\s+/c\s+at\s+", 
            "technique": "T1059",
            "sub_technique": ".003"
        },
        {
            "id": "bash_curl_download",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+curl\s+-O\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_wget_download",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+wget\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_base64_decode",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+base64\s+-d\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*bash", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_echo_base64_decode",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d\s*\|\s*bash", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_perl_http_download",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+perl\s+-e\s+['\"][^'\"]*http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_python_http_download",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+python\s+-c\s+['\"][^'\"]*http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "bash_curl_execute",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+curl\s+-O\s+http[s]?://.*\s+&&\s+(\S+)", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "cscript_vbs_execution",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*\.vbs\s+", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "mshta_vbs_execution",
            "pattern": r"(?:mshta)(?:\.exe)?\s+http[s]?://.*\.vbs\s*", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "rundll32_vbs_execution",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*\.vbs\s*,\s*.*", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_encoded_command",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_create_object",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*CreateObject\s*\(\s*\"Scripting\.FileSystemObject\"\s*\)", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_execute",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Execute\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_run",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Run\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_from_base64",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*FromBase64String\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "mshta_execute",
            "pattern": r"(?:mshta)(?:\.exe)?\s+.*Execute\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "rundll32_execute",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Execute\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "rundll32_run",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Run\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "rundll32_from_base64",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*FromBase64String\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "rundll32_eval",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Eval\s*\(", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "cscript_vbs_encoded_command_chain",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.vbs)", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "python_http_request",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*-c\s+['\"]import\s+urllib\.request;?\s*urllib\.request\.urlopen\(['\"]http[s]?://",
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
             "id": "python_certutil_download_execute",
            "pattern": r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", # certutil download and execute
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_requests_get",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_exec_base64_decode",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_os_system_curl",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*os\.system\s*\(\s*['\"]curl\s+-O\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_subprocess_wget",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*subprocess\.Popen\s*\(\s*['\"]wget\s+http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_os_system_python",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"]python\s+-c\s+['\"]import\s+urllib\.request;?\s*urllib\.request\.urlopen\(['\"]http[s]?://", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "python_exec_response_read",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*-c\s+['\"]import\s+urllib\.request;?\s*response\s*=\s*urllib\.request\.urlopen\(['\"]http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)", 
            "technique": "T1059",
            "sub_technique": ".006"
        },
        {
            "id": "cscript_js_execution",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*\.js\s+", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_js_execution",
            "pattern": r"(?:mshta)(?:\.exe)?\s+http[s]?://.*\.js\s*", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "rundll32_js_execution",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*\.js\s*,\s*.*", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_encoded_command",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_create_object",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*CreateObject\s*\(\s*\"MSScriptControl\.ScriptControl\"\s*\)", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_eval",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Eval\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_execute",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Execute\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_run",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*Run\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_from_base64",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*FromBase64String\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_js_eval",
            "pattern": r"(?:mshta)(?:\.exe)?\s+.*Eval\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "rundll32_js_eval",
            "pattern": r"(?:rundll32)(?:\.exe)?\s+.*Eval\s*\(", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "cscript_js_encoded_command_chain",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.js)", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_javascript",
            "pattern": r"(?i)\bmshta\.exe\b\s+javascript:", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "rundll32_javascript",
            "pattern": r"(?i)\brundll32\.exe\b\s+javascript:", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_http_file",
            "pattern": r"(?i)\bmshta\.exe\b\s+https?:\/\/[^\s]+\.hta\b", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_local_file",
            "pattern": r"(?i)\bmshta\.exe\b\s+.*\\(users|temp|appdata|downloads|public)\\[^\s]+\.hta\b", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_vbscript_url",
            "pattern": r"(?i)\bmshta\.exe\b\s+vbscript:", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_about_url",
            "pattern": r"(?i)\bmshta\.exe\b\s+about:", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "hta_application",
            "pattern": r"(?i)<hta:application>", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_http_html_file",
            "pattern": r"(?i)\bmshta\.exe\b\s+https?:\/\/[^\s]+\.(html?|php|asp|jsp)\b", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_activeX",
            "pattern": r"(?i)\bmshta\.exe\b.*(activexobject|xmlhttp|adodb\.stream)", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_eval",
            "pattern": r"(?i)\bmshta\.exe\b.*(eval\(|atob\(|chr\(|execute\()", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_chain_command",
            "pattern": r"(?i)(cmd\.exe|powershell\.exe|wscript\.exe|rundll32\.exe).*\bmshta\.exe\b", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        {
            "id": "mshta_command",
            "pattern": r"(?i)\bmshta\.exe\b\s+.+", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        
        # Design a few high confidence general patterns for Network Device CLI suspicious code execution using command patterns for technique T1059.008:
        {
            "id": "network_device_cli_wget",
            "pattern": r"(?:ssh|telnet)\s+.*\s+wget\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_curl",
            "pattern": r"(?:ssh|telnet)\s+.*\s+curl\s+-O\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_tftp",
            "pattern": r"\btftp(?:\.exe)?\s+(?:-i\s+)?(?:\d{1,3}(?:\.\d{1,3}){3}|\[[a-fA-F0-9:]+\])\s+(?:get|put)\s+\S+",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {   
            "id": "network_device_cli_certutil_download",
            "pattern": r"\bcertutil(?:\.exe)?\s+-urlcache\s+-f\s+\S+\s+\S+",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_bitsadmin_transfer",
            "pattern": r"\bbitsadmin(?:\.exe)?\s+/transfer\s+\S+\s+\S+\s+\S+",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_wmic_process_create",
            "pattern": r"\bwmic\s+process\s+call\s+create\s+\"?.+\"?",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_base64_decode",
            "pattern": r"(?:ssh|telnet)\s+.*\s+echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|ksh|zsh|dash)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_perl_download",
            "pattern": r"(?:ssh|telnet)\s+.*\s+perl\s+-e\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_python_download",
            "pattern": r"(?:ssh|telnet)\s+.*\s+python\s+-c\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_download_and_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+(curl\s+-O|wget|tftp\s+-g)\s+http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_execute_command",
            "pattern": r"(?:ssh|telnet)\s+.*\s+(bash|sh|ksh|zsh|dash|perl|python|php|ruby)(?:\.exe)?\s+",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_base64_decode_chain",
            "pattern": r"(?:ssh|telnet)\s+.*\s+echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|ksh|zsh|dash).*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_tftp_download_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+tftp\s+-g\s+http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_perl_download_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+perl\s+-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_python_download_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+python\s+-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_curl_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+curl\s+-O\s+http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_wget_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+wget\s+http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_execute_chain_command",
            "pattern": r"(?:ssh|telnet)\s+.*\s+(bash|sh|ksh|zsh|dash|perl|python|php|ruby)(?:\.exe)?\s+.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        #   Design a few high confidence general patterns for Cloud API (including native AWS, Azure, GCP) suspicious code execution 
        #   using command patterns for technique T1059.009:

        {
            "id": "cloud_api_aws_lambda_invoke",
            "pattern": r"aws\s+lambda\s+invoke\s+--function-name\s+\S+\s+--payload\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_azure_function_invoke",
            "pattern": r"az\s+functionapp\s+function\s+invoke\s+--name\s+\S+\s+--function-name\s+\S+\s+--data\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_gcp_cloud_function_invoke",
            "pattern": r"gcloud\s+functions\s+call\s+\S+\s+--data\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_aws_s3_cp",
            "pattern": r"aws\s+s3\s+cp\s+http[s]?://\S+\s+\S+",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_azure_storage_blob_download",
            "pattern": r"az\s+storage\s+blob\s+download\s+--container-name\s+\S+\s+--name\s+\S+\s+--file\s+\S+\s+--account-name\s+\S+",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_gcp_storage_cp",
            "pattern": r"gsutil\s+cp\s+gs://\S+\s+\S+",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_invoke_and_execute",
            "pattern": r"(aws\s+lambda\s+invoke|az\s+functionapp\s+function\s+invoke|gcloud\s+functions\s+call)\s+.*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_storage_download_and_execute",
            "pattern": r"(aws\s+s3\s+cp|az\s+storage\s+blob\s+download|gsutil\s+cp)\s+http[s]?://\S+.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_invoke_command",
            "pattern": r"(aws\s+lambda\s+invoke|az\s+functionapp\s+function\s+invoke|gcloud\s+functions\s+call)\s+.*",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_storage_download_command",
            "pattern": r"(aws\s+s3\s+cp|az\s+storage\s+blob\s+download|gsutil\s+cp)\s+http[s]?://\S+\s+\S+",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_invoke_chain_command",
            "pattern": r"(aws\s+lambda\s+invoke|az\s+functionapp\s+function\s+invoke|gcloud\s+functions\s+call)\s+.*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".009"
        },
        {
            "id": "cloud_api_storage_download_chain_command",
            "pattern": r"(aws\s+s3\s+cp|az\s+storage\s+blob\s+download|gsutil\s+cp)\s+http[s]?://\S+.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".009"
        },
            # Design a few GENERAL patterns for spotting AutoHotKey & AutoIT suspicious automated scripts execution using command patterns for technique T1059.010:
        
        {
            "id": "autohotkey_download_execute",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*(http[s]?://\S+).*&&\s+(\S+\.ahk)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_download_execute",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*(http[s]?://\S+).*&&\s+(\S+\.au3)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_encoded_command",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_encoded_command",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_run_script",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*\S+\.ahk",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_run_script",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*\S+\.au3",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_download",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*http[s]?://\S+",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_download",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*http[s]?://\S+",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_chain_command",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*\S+\.ahk.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_chain_command",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*\S+\.au3.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_base64_decode",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*base64decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_base64_decode",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*Base64Decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_download_base64_decode",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*http[s]?://\S+.*base64decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_download_base64_decode",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*http[s]?://\S+.*Base64Decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_download_execute_chain",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*(http[s]?://\S+).*&&\s+(\S+\.ahk).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_download_execute_chain",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*(http[s]?://\S+).*&&\s+(\S+\.au3).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_base64_decode_chain",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*base64decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_base64_decode_chain",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*Base64Decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_encoded_command_chain",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_encoded_command_chain",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_chain_multiple_commands",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*\S+\.ahk.*\s+&&\s+(\S+).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_chain_multiple_commands",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*\S+\.au3.*\s+&&\s+(\S+).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autohotkey_encoded_command_multiple_chain",
            "pattern": r"AutoHotkey(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },
        {
            "id": "autoit_encoded_command_multiple_chain",
            "pattern": r"AutoIt3(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+).*&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".010"
        },

            # Design a few GENERAL patterns for spotting Lua suspicious code execution using command patterns for technique T1059.011:
        {
            "id": "lua_oneliner_download",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*-e\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_loadstring_url",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*loadstring\s*\(.*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_require_socket_url",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*require\s*\(\s*['\"]socket['\"]\s*\).*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_os_execute_curl",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*os\.execute\s*\(\s*['\"]curl\s+-O\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_os_execute_wget",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*os\.execute\s*\(\s*['\"]wget\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_base64_decode_loadstring",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*base64\.decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)\s*\|\s*loadstring",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_base64_decode_loadfile",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*base64\.decode\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)\s*\|\s*loadfile",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_io_popen_curl",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*io\.popen\s*\(\s*['\"]curl\s+-O\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_io_popen_wget",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*io\.popen\s*\(\s*['\"]wget\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "lua_download_and_execute",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "hypervisor_cli_url_download",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_requests_download",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_base64_exec",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_system_curl",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*system\s*\(\s*['\"]curl\s+-O\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_subprocess_wget",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*subprocess\s*\(\s*['\"]wget\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_nested_download",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"](virsh|VBoxManage|qm|xe|govc)\s+-c\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "hypervisor_cli_download_execute",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_url_download",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_requests_download",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*import\s+requests;?\s*requests\.get\(['\"]http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_base64_exec",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_system_curl",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*system\s*\(\s*['\"]curl\s+-O\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_subprocess_wget",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*subprocess\s*\(\s*['\"]wget\s+http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_nested_download",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*import\s+os;?\s*os\.system\s*\(\s*['\"](docker|kubectl|podman|crictl)\s+-c\s+['\"][^'\"]*http[s]?://",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_download_execute",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)",
            "technique": "T1059",
            "sub_technique": ".012"
        } 
    ]