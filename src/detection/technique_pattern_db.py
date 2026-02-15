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
            "id": "ps_encoded_command",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]n(codedCommand)?\s+[A-Za-z0-9+/=]{20,}", # EncodedCommand with base64 string
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
            "id": "ps_frombase64string_iex",
            "pattern": r"(?:powershell|pwsh)(?:\.exe)?\s+.*FromBase64String\s*\(.*\)\s*\|\s*(iex|Invoke-Expression)", # Base64 decode piped to IEX
            "technique": "T1059",
            "sub_technique": ".001"
        },

        
        # Design a few GENERAL patterns for spotting Apple Script suspicious code execution using command patterns for technique T1059.002:
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
            "id": "cmd_powershell_encoded_command",
            "pattern": r"cmd\.exe\s+/c\s+powershell\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
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
            "id": "cmd_powershell_encoded_command_s",
            "pattern": r"cmd\.exe\s+/c\s+powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", 
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
            "id": "bash_curl_execute",
            "pattern": r"/bin/(bash|sh|zsh|ksh|dash)(?:\.exe)?\s+-c\s+curl\s+-O\s+http[s]?://.*\s+&&\s+(\S+)", 
            "technique": "T1059",
            "sub_technique": ".004"
        },
        {
            "id": "cscript_vbs_encoded_command",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
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
            "id": "cscript_vbs_encoded_command_chain",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.vbs)", 
            "technique": "T1059",
            "sub_technique": ".005"
        },
        {
            "id": "python_exec_base64_decode",
            "pattern": r"(?:python|python3|py)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)", 
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
            "id": "cscript_js_encoded_command",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
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
            "id": "cscript_js_encoded_command_chain",
            "pattern": r"(?:cscript|wscript)(?:\.exe)?\s+.*-e\s+[A-Za-z0-9+/=]{20,}.*\s+&&\s+(\S+\.js)", 
            "technique": "T1059",
            "sub_technique": ".007"
        },
        
        # Design a few high confidence general patterns for Network Device CLI suspicious code execution using command patterns for technique T1059.008:
        {
            "id": "network_device_cli_download_and_execute",
            "pattern": r"(?:ssh|telnet)\s+.*\s+(curl\s+-O|wget|tftp\s+-g)\s+http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        {
            "id": "network_device_cli_base64_decode_chain",
            "pattern": r"(?:ssh|telnet)\s+.*\s+echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|ksh|zsh|dash).*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".008"
        },
        #   Design a few high confidence general patterns for Cloud API (including native AWS, Azure, GCP) suspicious code execution 
        #   using command patterns for technique T1059.009:

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

            # Design a few GENERAL patterns for spotting Lua suspicious code execution using command patterns for technique T1059.011:
        {
            "id": "lua_loadstring_url",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*loadstring\s*\(.*http[s]?://",
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
            "id": "lua_download_and_execute",
            "pattern": r"(?:lua|luajit)(?:\.exe)?\s+.*-e\s+['\"][^'\"]*http[s]?://.*\s+&&\s+(\S+)",
            "technique": "T1059",
            "sub_technique": ".011"
        },
        {
            "id": "hypervisor_cli_base64_exec",
            "pattern": r"(?:virsh|VBoxManage|qm|xe|govc)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)",
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
            "id": "container_cli_base64_exec",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*exec\s*\(.*base64\.b64decode\(['\"][A-Za-z0-9+/=]{20,}['\"]\).*\)",
            "technique": "T1059",
            "sub_technique": ".012"
        },
        {
            "id": "container_cli_download_execute",
            "pattern": r"(?:docker|kubectl|podman|crictl)(?:\.exe)?\s+.*-c\s+['\"][^'\"]*http[s]?://.*\s+&&\s+exec\(response\.read\(\)\)",
            "technique": "T1059",
            "sub_technique": ".012"
        },

        # --------------------------------------------------------------
        # List of T1218 sub-technique IDs with associated regex patterns 
        # --------------------------------------------------------------

        # System Binary Proxy Execution (T1218) - Mshta
        {
            "id": "mshta_proxy",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b",
            "technique": "T1218",
            "sub_technique": ".005"
        },

        # Design a few CRITICAL patterns for spotting Compiled HTML File as suspicious code execution using command patterns for technique T1218.001:
        {
            "id": "mshta_remote_hta_url",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+https?://[^\s]+\.hta\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_remote_js_url",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+https?://[^\s]+\.js\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_remote_html_like_url",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+https?://[^\s]+\.(?:html?|php|asp|jsp)\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_local_suspicious_hta",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+.*\\(?:users|temp|appdata|downloads|public)\\[^\s]+\.hta\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "hta_application_marker",
            "pattern": r"(?i)<hta:application>",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_script_protocol_obfuscated",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+['\"]?(?:javascript|vbscript):.*\b(eval\(|atob\(|fromcharcode\(|string\.fromcharcode\(|unescape\(|chr\(|execute\()\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_script_protocol_activex",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+['\"]?(?:javascript|vbscript):.*\b(activexobject|xmlhttp|adodb\.stream)\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_chain_to_shell",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b[^&|]*(&&|\|)[^&|]*\b(cmd\.exe|powershell\.exe|wscript\.exe|rundll32\.exe)\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },
        {
            "id": "mshta_shell_chain_to_mshta",
            "pattern": r"(?i)\b(cmd\.exe|powershell\.exe|wscript\.exe|rundll32\.exe)\b[^&|]*(&&|\|)[^&|]*\bmshta(?:\.exe)?\b",
            "technique": "T1218",
            "sub_technique": ".001"
        },

        # Design a few CRITICAL patterns for spotting control.exe to proxy execution under technique T1218.002:
        {
            "id": "control_panel_cpl_file",
            "pattern": r"(?i)\bcontrol(?:\.exe)?\b\s+.*\.cpl\b",
            "technique": "T1218",
            "sub_technique": ".002"
        },
        {
            "id": "suspicious_path_cpl",
            "pattern": r"(?i)\bcontrol(?:\.exe)?\b\s+.*(users|programdata|temp|appdata|\\).+\.cpl\b",
            "technique": "T1218",
            "sub_technique": ".002"
        },
        {
            "id": "control_runDLL_invokation",
            "pattern": r"(?i)\bcontrol(?:\.exe)?\b\s+shell32\.dll,Control_RunDLL\b",
            "technique": "T1218",
            "sub_technique": ".002"
        },
        {
            "id": "control_panel_chain_command",
            "pattern": r"(?i)\bcontrol(?:\.exe)?\b[^&|]*(&&|\|)[^&|]*",
            "technique": "T1218",
            "sub_technique": ".002"
        },

        # Design a few CRITICAL patterns for spotting CMSTP under technique T1218.003:

        {
            "id": "cmstp_inf_execution",
            "pattern": r"(?i)\bcmstp(?:\.exe)?\b\s+.*\.inf\b",
            "technique": "T1218",
            "sub_technique": ".003"
        },
        {
            "id": "cmstp_silent_install",
            "pattern": r"(?i)\bcmstp(?:\.exe)?\b\s+.*\b/(s|au)\b",
            "technique": "T1218",
            "sub_technique": ".003"
        },
        {
            "id": "cmstp_suspicious_path",
            "pattern": r"(?i)\bcmstp(?:\.exe)?\b\s+.*(users|programdata|temp|appdata|\\\\).+\.inf\b",
            "technique": "T1218",
            "sub_technique": ".003"
        },
        {
            "id": "cmstp_chain_operator",
            "pattern": r"(?i)\bcmstp(?:\.exe)?\b[^&|]*(&&|\|)[^&|]*",
            "technique": "T1218",
            "sub_technique": ".003"
        },

        # Design a few CRITICAL patterns for spotting InstallUtil abuse under technique T1218.004:
        {
            "id": "installutil_uninstall_user_path",
            "pattern": r"(?i)\binstallutil(?:\.exe)?\b\s+/u\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.(?:dll|exe)\b",
            "technique": "T1218",
            "sub_technique": ".004"
        },
        {
            "id": "installutil_log_suppression_user_path",
            "pattern": r"(?i)\binstallutil(?:\.exe)?\b\s+.*(?:/logfile=|/logtoconsole=false).*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.(?:dll|exe)\b",
            "technique": "T1218",
            "sub_technique": ".004"
        },

        # Design a few CRITICAL patterns for spotting Mshta abuse under technique T1218.005:
        {
            "id": "mshta_getobject_scriptlet",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+(?:javascript|vbscript):.*getobject\(\s*\"?script:https?://",
            "technique": "T1218",
            "sub_technique": ".005"
        },
        {
            "id": "mshta_inline_execute_chain",
            "pattern": r"(?i)\bmshta(?:\.exe)?\b\s+(?:javascript|vbscript):.*\bexecute\(.*\)\b",
            "technique": "T1218",
            "sub_technique": ".005"
        },

        # Design a few CRITICAL patterns for spotting Msiexec abuse under technique T1218.007:
        {
            "id": "msiexec_remote_msi",
            "pattern": r"(?i)\bmsiexec(?:\.exe)?\b\s+/i\s+https?://[^\s]+\.msi\b",
            "technique": "T1218",
            "sub_technique": ".007"
        },
        {
            "id": "msiexec_unc_msi",
            "pattern": r"(?i)\bmsiexec(?:\.exe)?\b\s+/i\s+\\\\[^\s]+\.msi\b",
            "technique": "T1218",
            "sub_technique": ".007"
        },

        # Design a few CRITICAL patterns for spotting Odbcconf abuse under technique T1218.008:
        {
            "id": "odbcconf_regsvr_user_path",
            "pattern": r"(?i)\bodbcconf(?:\.exe)?\b\s+/s\s+/a\s+\{regsvr\s+\"?.*\\(?:users|temp|appdata|programdata|public)\\[^\"\s]+\.dll\"?\}",
            "technique": "T1218",
            "sub_technique": ".008"
        },

        # Design a few CRITICAL patterns for spotting Regsvcs/Regasm abuse under technique T1218.009:
        {
            "id": "regsvcs_codebase_user_path",
            "pattern": r"(?i)\bregsvcs(?:\.exe)?\b\s+/(?:codebase|u)\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.(?:dll|exe)\b",
            "technique": "T1218",
            "sub_technique": ".009"
        },
        {
            "id": "regasm_codebase_user_path",
            "pattern": r"(?i)\bregasm(?:\.exe)?\b\s+/(?:codebase|u)\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.(?:dll|exe)\b",
            "technique": "T1218",
            "sub_technique": ".009"
        },

        # Design a few CRITICAL patterns for spotting Regsvr32 abuse under technique T1218.010:
        {
            "id": "regsvr32_remote_sct",
            "pattern": r"(?i)\bregsvr32(?:\.exe)?\b\s+/s\s+/n\s+/u\s+/i:https?://[^\s]+\.sct\b\s+scrobj\.dll\b",
            "technique": "T1218",
            "sub_technique": ".010"
        },
        {
            "id": "regsvr32_local_sct_user_path",
            "pattern": r"(?i)\bregsvr32(?:\.exe)?\b\s+/s\s+/n\s+/u\s+/i:.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.sct\b\s+scrobj\.dll\b",
            "technique": "T1218",
            "sub_technique": ".010"
        },

        # Design a few CRITICAL patterns for spotting Rundll32 abuse under technique T1218.011:
        {
            "id": "rundll32_mshtml_runhtmlapplication",
            "pattern": r"(?i)\brundll32(?:\.exe)?\b\s+javascript:.*mshtml,runhtmlapplication",
            "technique": "T1218",
            "sub_technique": ".011"
        },
        {
            "id": "rundll32_user_dll_export",
            "pattern": r"(?i)\brundll32(?:\.exe)?\b\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.dll\s*,\s*[^\s,]+",
            "technique": "T1218",
            "sub_technique": ".011"
        },
        {
            "id": "rundll32_dll_ordinal",
            "pattern": r"(?i)\brundll32(?:\.exe)?\b\s+[^\s]+\.dll\s*,\s*#\d+",
            "technique": "T1218",
            "sub_technique": ".011"
        },

        # Design a few CRITICAL patterns for spotting Verclsid abuse under technique T1218.012:
        {
            "id": "verclsid_clsid_execute",
            "pattern": r"(?i)\bverclsid(?:\.exe)?\b\s+/s\s+/c\s+\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
            "technique": "T1218",
            "sub_technique": ".012"
        },

        # Design a few CRITICAL patterns for spotting Mavinject abuse under technique T1218.013:
        {
            "id": "mavinject_injectrunning",
            "pattern": r"(?i)\bmavinject(?:\.exe)?\b\s+\d+\s+/injectrunning\s+[^\s]+\.dll\b",
            "technique": "T1218",
            "sub_technique": ".013"
        },
        {
            "id": "mavinject_hmodule_inject",
            "pattern": r"(?i)\bmavinject(?:\.exe)?\b\s+\d+\s+/hmodule=0x[0-9a-f]+\s+[^\s]+\.dll\b",
            "technique": "T1218",
            "sub_technique": ".013"
        },

        # Design a few CRITICAL patterns for spotting MMC abuse under technique T1218.014:
        {
            "id": "mmc_embedding_user_msc",
            "pattern": r"(?i)\bmmc(?:\.exe)?\b\s+-embedding\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.msc\b",
            "technique": "T1218",
            "sub_technique": ".014"
        },
        {
            "id": "mmc_author_mode_user_msc",
            "pattern": r"(?i)\bmmc(?:\.exe)?\b\s+.*\\(?:users|temp|appdata|programdata|public)\\[^\s]+\.msc\b\s+/a\b",
            "technique": "T1218",
            "sub_technique": ".014"
        },

        # Design a few CRITICAL patterns for spotting Electron app abuse under technique T1218.015:
        {
            "id": "electron_gpu_launcher_shell",
            "pattern": r"(?i)\b(?:chrome|teams|slack|discord|signal|electron|code)(?:\.exe)?\b.*--gpu-launcher=\"?[^\"]*(?:cmd\.exe|powershell\.exe|/bin/(?:sh|bash|zsh))",
            "technique": "T1218",
            "sub_technique": ".015"
        },

        # --------------------------------------------------------------
        # List of T1027 sub-technique IDs with associated regex patterns 
        # --------------------------------------------------------------

        {
            "id": "js_string_concat_obfuscation",
            "pattern": r"(?i)javascript:.*'[^']+'\s*\+\s*'[^']+'",
            "technique": "T1027",
            "sub_technique": ".001"
        },
        {
            "id": "binary_padding_dd_append",
            "pattern": r"(?i)\bdd\b.*\bif=/dev/zero\b.*\bof=\S+\.(?:exe|dll|bin|elf|so|dylib)\b.*\bseek=\d+\b.*\bconv=notrunc\b",
            "technique": "T1027",
            "sub_technique": ".001"
        },
        {
            "id": "software_packing_tools",
            "pattern": r"(?i)\b(upx|mpress|aspack|themida|vmprotect|obsidium)\b.*\.(?:exe|dll|elf|so|dylib|bin)\b",
            "technique": "T1027",
            "sub_technique": ".002"
        },
        {
            "id": "steganography_steghide_embed_extract",
            "pattern": r"(?i)\bsteghide\b\s+(?:embed|extract)\b.*\.(?:png|jpe?g|bmp|gif|wav)\b",
            "technique": "T1027",
            "sub_technique": ".003"
        },
        {
            "id": "steganography_invoke_psimage",
            "pattern": r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*\bInvoke-PSImage\b",
            "technique": "T1027",
            "sub_technique": ".003"
        },
        {
            "id": "compile_after_delivery_dotnet",
            "pattern": r"(?i)\b(?:csc|ilasm|msbuild)(?:\.exe)?\b.*\\(?:users|temp|appdata|downloads)\\[^\s]+\.(?:cs|vb|txt)\b",
            "technique": "T1027",
            "sub_technique": ".004"
        },
        {
            "id": "compile_after_delivery_gcc_tmp",
            "pattern": r"(?i)\b(?:gcc|g\+\+|clang)\b.*\s(?:/tmp|/var/tmp|/home/[^/]+/Downloads)/[^\s]+\.(?:c|cc|cpp)\b.*\s-o\s+\S+",
            "technique": "T1027",
            "sub_technique": ".004"
        },
        {
            "id": "indicator_removal_find_avsignature",
            "pattern": r"(?i)\bFind-AVSignature\b",
            "technique": "T1027",
            "sub_technique": ".005"
        },
        {
            "id": "html_smuggling_data_url",
            "pattern": r"(?i)data:application/(?:octet-stream|zip|x-msdownload|x-msi);base64,",
            "technique": "T1027",
            "sub_technique": ".006"
        },
        {
            "id": "html_smuggling_blob_download",
            "pattern": r"(?i)\b(?:Blob|msSaveOrOpenBlob|msSaveBlob|URL\.createObjectURL)\b.*\bdownload=",
            "technique": "T1027",
            "sub_technique": ".006"
        },
        {
            "id": "dynamic_api_resolution_winapi",
            "pattern": r"(?i)\b(GetProcAddress|LdrGetProcedureAddress)\b.*\b(LoadLibrary|LdrLoadDll)\b",
            "technique": "T1027",
            "sub_technique": ".007"
        },
        {
            "id": "stripped_payloads_strip_tool",
            "pattern": r"(?i)\b(?:strip|llvm-strip)\b.*\b(--strip-all|--strip-unneeded|-s)\b.*\.(?:elf|so|bin|exe|dylib)\b",
            "technique": "T1027",
            "sub_technique": ".008"
        },
        {
            "id": "embedded_payload_base64_pe_header",
            "pattern": r"(?i)TVqQAAMAAAAEAAAA",
            "technique": "T1027",
            "sub_technique": ".009"
        },
        {
            "id": "command_obfuscation_tools",
            "pattern": r"(?i)\b(Invoke-Obfuscation|Invoke-DOSfuscation|bashfuscator)\b",
            "technique": "T1027",
            "sub_technique": ".010"
        },
        {
            "id": "fileless_storage_registry_blob",
            "pattern": r"(?i)\breg(?:\.exe)?\b\s+add\b.*\\(?:Software|Classes|Microsoft\\Windows\\CurrentVersion)\\[^\s]+\s+/t\s+REG_(?:BINARY|SZ)\s+/d\s+[A-Fa-f0-9]{100,}",
            "technique": "T1027",
            "sub_technique": ".011"
        },
        {
            "id": "fileless_storage_dev_shm_exec",
            "pattern": r"(?i)\b(?:chmod\s+\+x\s+/(?:dev|run)/shm/[^\s]+|/(?:dev|run)/shm/[^\s]+\b)",
            "technique": "T1027",
            "sub_technique": ".011"
        },
        {
            "id": "lnk_icon_smuggling_url",
            "pattern": r"(?i)\.lnk\b.*\b(IconLocation|IconEnvironmentDataBlock)\b.*(https?://|\\\\[^\\\s]+\\)",
            "technique": "T1027",
            "sub_technique": ".012"
        },
        {
            "id": "encrypted_file_openssl_enc",
            "pattern": r"(?i)\bopenssl\b\s+enc\s+-aes-(?:128|192|256)-(?:cbc|gcm)\b.*\b-in\b\s+\S+\s+\b-out\b\s+\S+",
            "technique": "T1027",
            "sub_technique": ".013"
        },
        {
            "id": "encrypted_file_gpg_symmetric",
            "pattern": r"(?i)\bgpg\b\s+(?:-c|--symmetric)\b.*\b\S+\.(?:txt|docx|xlsx|pdf|zip|7z|rar|exe|dll)\b",
            "technique": "T1027",
            "sub_technique": ".013"
        },
        {
            "id": "polymorphic_code_msfvenom_encoder",
            "pattern": r"(?i)\bmsfvenom\b.*\s-e\s+\S+",
            "technique": "T1027",
            "sub_technique": ".014"
        },
        {
            "id": "compression_archive_with_executables",
            "pattern": r"(?i)\b(?:7z|rar|winrar|zip)\b\s+a\b.*\.(?:zip|7z|rar)\b.*\.(?:exe|dll|js|vbs|ps1|bat|cmd|msi|scr)\b",
            "technique": "T1027",
            "sub_technique": ".015"
        },
        {
            "id": "junk_code_insertion_js_obfuscator",
            "pattern": r"(?i)\bjavascript-obfuscator\b.*\b--deadCodeInjection\b",
            "technique": "T1027",
            "sub_technique": ".016"
        },
        {
            "id": "svg_smuggling_script_payload",
            "pattern": r"(?i)<svg[^>]*>.*<script[^>]*>.*(?:atob\(|data:application/|Blob\()",
            "technique": "T1027",
            "sub_technique": ".017"
        },
    ]