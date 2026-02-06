PATTERN_METADATA = {

    # -------------------------
    # PowerShell
    # -------------------------
    "ps_encoded_command": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "Encoded PowerShell execution",
        "indicators": ["-enc", "base64"],
        "base_confidence": 0.9,
    },

    "ps_reflection_assembly_load": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Reflection Assembly Load",
        "indicators": ["Reflection.Assembly", "Load"],
        "base_confidence": 0.8,
    },

    "ps_downloadstring": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell download cradle",
        "indicators": ["DownloadString", "WebClient"],
        "base_confidence": 0.85,
    },

    "ps_add_type_typedefinition": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Add-Type with TypeDefinition",
        "indicators": ["Add-Type", "TypeDefinition"],
        "base_confidence": 0.8,
    },

    "ps_web_request": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell web request commands",
        "indicators": ["Invoke-WebRequest", "Invoke-RestMethod", "iwr", "irm"],
        "base_confidence": 0.75,
    },

    "ps_web_request_direct_url_piped_iex": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell web request piped to execution",
        "indicators": ["direct_url", "pipe_to_iex"],
        "base_confidence": 0.95,
    },

    "ps_web_request_generic_piped_iex": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell any web request piped to execution",
        "indicators": ["pipe_to_iex"],
        "base_confidence": 0.75,
    },

    "ps_downloadstring_newobject": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell DownloadString method via New-Object",
        "indicators": ["New-Object", "DownloadString", "WebClient"],
        "base_confidence": 0.85,
    },

    "ps_downloadfile": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell DownloadFile method usage",
        "indicators": ["DownloadFile", "WebClient"],
        "base_confidence": 0.8,
    },

    "ps_webrequest_getresponse": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell WebRequest GetResponse method usage",
        "indicators": ["GetResponse", "WebRequest"],
        "base_confidence": 0.75,
    },

    "ps_add_type_dllimport": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Add-Type with DllImport usage",
        "indicators": ["Add-Type", "DllImport"],
        "base_confidence": 0.8,
    },

    "ps_frombase64string": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell FromBase64String method usage",
        "indicators": ["FromBase64String"],
        "base_confidence": 0.8,
    },

    "ps_invoke_command_scriptblock": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Invoke-Command with ScriptBlock usage",
        "indicators": ["Invoke-Command", "ScriptBlock"],
        "base_confidence": 0.8,
    },

    "ps_start_process_argumentlist": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Start-Process with ArgumentList usage",
        "indicators": ["Start-Process", "ArgumentList"],
        "base_confidence": 0.8,
    },

    "ps_executionpolicy_bypass": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell ExecutionPolicy Bypass",
        "indicators": ["-ExecutionPolicy", "Bypass"],
        "base_confidence": 0.85,
    },

    "ps_noprofile": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell NoProfile flag usage",
        "indicators": ["-NoProfile"],
        "base_confidence": 0.7,
    },

    "ps_hidden_windowstyle": {
        "launcher": "powershell",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell Hidden WindowStyle flag usage",
        "indicators": ["-WindowStyle", "Hidden"],
        "base_confidence": 0.7,
    },

    # -------------------------
    # AppleScript
    # -------------------------
    "as_download_from_url": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript downloading from URL",
        "indicators": ["osascript", "http", "https"],
        "base_confidence": 0.75,
    },

    "as_do_shell_script_with_url": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript do shell script with URL",
        "indicators": ["osascript", "do shell script", "http"],
        "base_confidence": 0.8,
    },

    "as_curl_download": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript curl download",
        "indicators": ["osascript", "do shell script", "curl", "-O"],
        "base_confidence": 0.85,
    },

    "as_wget_download": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript wget download",
        "indicators": ["osascript", "do shell script", "wget"],
        "base_confidence": 0.85,
    },

    "as_base64_decode_to_bash": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript base64 decode piped to bash",
        "indicators": ["osascript", "do shell script", "base64", "-D", "bash"],
        "base_confidence": 0.9,
    },

    "as_download_and_execute": {
        "launcher": "osascript",
        "interpreter": "applescript",
        "rule_scope": "applescript",
        "behavior": "AppleScript download and execute",
        "indicators": ["osascript", "http", "&&"],
        "base_confidence": 0.9,
    },

    # -------------------------
    # Windows Command Shell
    # -------------------------
    "cmd_certutil_urlcache_split": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command certutil urlcache split download",
        "indicators": ["cmd.exe", "certutil", "-urlcache", "-split"],
        "base_confidence": 0.9,
    },

    "cmd_bitsadmin_transfer": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command bitsadmin file transfer",
        "indicators": ["cmd.exe", "bitsadmin", "/transfer"],
        "base_confidence": 0.85,
    },

    "cmd_powershell_encoded_command": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command executing PowerShell with encoded command",
        "indicators": ["cmd.exe", "powershell", "-e", "base64"],
        "base_confidence": 0.9,
    },

    "cmd_wmic_process_call_create": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command WMI process creation",
        "indicators": ["cmd.exe", "wmic", "process", "call", "create"],
        "base_confidence": 0.85,
    },

    "cmd_start_http_url": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command start with HTTP URL",
        "indicators": ["cmd.exe", "start", "http"],
        "base_confidence": 0.7,
    },

    "cmd_ftp_script": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command FTP script execution",
        "indicators": ["cmd.exe", "ftp", "-s"],
        "base_confidence": 0.8,
    },

    "cmd_regsvr32_http_url": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command regsvr32 with HTTP URL",
        "indicators": ["cmd.exe", "regsvr32", "/i", "http"],
        "base_confidence": 0.9,
    },

    "cmd_mshta_http_url": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command mshta with HTTP URL",
        "indicators": ["cmd.exe", "mshta", "http"],
        "base_confidence": 0.9,
    },

    "cmd_rundll32_url_handler": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command rundll32 URL handler",
        "indicators": ["cmd.exe", "rundll32", "url.dll", "FileProtocolHandler"],
        "base_confidence": 0.85,
    },

    "cmd_certutil_urlcache_split_f": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command certutil urlcache split with force flag",
        "indicators": ["cmd.exe", "certutil", "-urlcache", "-split", "-f"],
        "base_confidence": 0.9,
    },

    "cmd_bitsadmin_transfer_s": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command bitsadmin transfer with HTTP",
        "indicators": ["cmd.exe", "bitsadmin", "/transfer", "http"],
        "base_confidence": 0.85,
    },

    "cmd_powershell_encoded_command_s": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command executing PowerShell with encoded command",
        "indicators": ["cmd.exe", "powershell", "-e", "-enc", "base64"],
        "base_confidence": 0.9,
    },

    "cmd_start_http_url_executable": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command start with HTTP URL to executable",
        "indicators": ["cmd.exe", "start", "http", "exe", "dll", "js", "vbs"],
        "base_confidence": 0.9,
    },

    "cmd_rundll32_url_handler_escaped": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command rundll32 URL handler",
        "indicators": ["cmd.exe", "rundll32", "url.dll", "FileProtocolHandler"],
        "base_confidence": 0.85,
    },

    "cmd_certutil_urlcache_split_f_chain": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command certutil urlcache split with command chaining",
        "indicators": ["cmd.exe", "certutil", "-urlcache", "-split", "-f", "&&"],
        "base_confidence": 0.95,
    },

    "cmd_bitsadmin_transfer_f": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command bitsadmin transfer with command chaining",
        "indicators": ["cmd.exe", "bitsadmin", "/transfer", "http", "&&"],
        "base_confidence": 0.95,
    },

    "cmd_execute_command": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command executing interpreters",
        "indicators": ["cmd.exe", "/c", "powershell", "wscript", "cscript", "mshta"],
        "base_confidence": 0.75,
    },

    "wscript_shell_run_cmd": {
        "launcher": "mshta",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command shell execution via WScript.Shell.Run",
        "indicators": ["wscript.shell", "cmd.exe"],
        "base_confidence": 0.85,
    },

    "wscript_shell_run_powershell": {
        "launcher": "mshta",
        "interpreter": "powershell",
        "rule_scope": "powershell",
        "behavior": "PowerShell execution via WScript.Shell.Run",
        "indicators": ["powershell", "-nop", "-c"],
        "base_confidence": 0.85,
    },

    "cmd_schtasks_create": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command scheduled task creation",
        "indicators": ["cmd.exe", "schtasks", "/create"],
        "base_confidence": 0.8,
    },

    "cmd_at_command": {
        "launcher": "cmd.exe",
        "interpreter": "cmd",
        "rule_scope": "cmd",
        "behavior": "Command AT task scheduling",
        "indicators": ["cmd.exe", "at"],
        "base_confidence": 0.7,
    },

    # -------------------------
    # Bash/Shell
    # -------------------------
    "bash_curl_download": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash curl download with output redirection",
        "indicators": ["bash", "-c", "curl", "-O", "http"],
        "base_confidence": 0.85,
    },

    "bash_wget_download": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash wget download",
        "indicators": ["bash", "-c", "wget", "http"],
        "base_confidence": 0.85,
    },

    "bash_base64_decode": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash base64 decode piped to bash",
        "indicators": ["bash", "-c", "base64", "-d", "bash"],
        "base_confidence": 0.9,
    },

    "bash_echo_base64_decode": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash echo base64 decode chain",
        "indicators": ["bash", "-c", "echo", "base64", "-d", "bash"],
        "base_confidence": 0.9,
    },

    "bash_perl_http_download": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash Perl HTTP download",
        "indicators": ["bash", "-c", "perl", "-e", "http"],
        "base_confidence": 0.8,
    },

    "bash_python_http_download": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash Python HTTP download",
        "indicators": ["bash", "-c", "python", "-c", "http"],
        "base_confidence": 0.8,
    },

    "bash_curl_execute": {
        "launcher": "bash",
        "interpreter": "bash",
        "rule_scope": "bash",
        "behavior": "Bash curl download and execute",
        "indicators": ["bash", "-c", "curl", "-O", "http", "&&"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # VBScript
    # -------------------------
    "cscript_vbs_execution": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript file execution via cscript",
        "indicators": ["cscript", ".vbs"],
        "base_confidence": 0.8,
    },

    "mshta_vbs_execution": {
        "launcher": "mshta",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript execution via mshta with URL",
        "indicators": ["mshta", ".vbs", "http"],
        "base_confidence": 0.85,
    },

    "rundll32_vbs_execution": {
        "launcher": "rundll32",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript execution via rundll32",
        "indicators": ["rundll32", ".vbs"],
        "base_confidence": 0.8,
    },

    "cscript_vbs_encoded_command": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript encoded command execution",
        "indicators": ["cscript", "-e", "base64"],
        "base_confidence": 0.85,
    },

    "cscript_vbs_create_object": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript CreateObject usage",
        "indicators": ["cscript", "CreateObject", "FileSystemObject"],
        "base_confidence": 0.75,
    },

    "cscript_vbs_execute": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Execute method",
        "indicators": ["cscript", "Execute"],
        "base_confidence": 0.8,
    },

    "cscript_vbs_run": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Run method",
        "indicators": ["cscript", "Run"],
        "base_confidence": 0.8,
    },

    "cscript_vbs_from_base64": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript FromBase64String method",
        "indicators": ["cscript", "FromBase64String"],
        "base_confidence": 0.85,
    },

    "mshta_execute": {
        "launcher": "mshta",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Execute via mshta",
        "indicators": ["mshta", "Execute"],
        "base_confidence": 0.8,
    },

    "rundll32_execute": {
        "launcher": "rundll32",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Execute via rundll32",
        "indicators": ["rundll32", "Execute"],
        "base_confidence": 0.8,
    },

    "rundll32_run": {
        "launcher": "rundll32",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Run via rundll32",
        "indicators": ["rundll32", "Run"],
        "base_confidence": 0.8,
    },

    "rundll32_from_base64": {
        "launcher": "rundll32",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript FromBase64String via rundll32",
        "indicators": ["rundll32", "FromBase64String"],
        "base_confidence": 0.85,
    },

    "rundll32_eval": {
        "launcher": "rundll32",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript Eval via rundll32",
        "indicators": ["rundll32", "Eval"],
        "base_confidence": 0.85,
    },

    "cscript_vbs_encoded_command_chain": {
        "launcher": "cscript",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript encoded command with chaining",
        "indicators": ["cscript", "-e", "base64", "&&"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # Python
    # -------------------------
    "python_http_request": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python urllib HTTP request",
        "indicators": ["python", "-c", "urllib.request", "urlopen", "http"],
        "base_confidence": 0.8,
    },

    "python_certutil_download_execute": {
        "launcher": "cmd.exe",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python certutil download and execute",
        "indicators": ["cmd.exe", "certutil", "-urlcache", "&&"],
        "base_confidence": 0.9,
    },

    "python_requests_get": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python requests HTTP GET",
        "indicators": ["python", "-c", "requests", "get", "http"],
        "base_confidence": 0.75,
    },

    "python_exec_base64_decode": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python exec with base64 decode",
        "indicators": ["python", "-c", "exec", "base64", "b64decode"],
        "base_confidence": 0.9,
    },

    "python_os_system_curl": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python os.system curl download",
        "indicators": ["python", "-c", "os.system", "curl", "-O"],
        "base_confidence": 0.85,
    },

    "python_subprocess_wget": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python subprocess wget",
        "indicators": ["python", "-c", "subprocess", "wget", "http"],
        "base_confidence": 0.85,
    },

    "python_os_system_python": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python nested os.system with urllib",
        "indicators": ["python", "-c", "os.system", "urllib", "urlopen"],
        "base_confidence": 0.9,
    },

    "python_exec_response_read": {
        "launcher": "python",
        "interpreter": "python",
        "rule_scope": "python",
        "behavior": "Python exec response read",
        "indicators": ["python", "-c", "urlopen", "response.read", "exec"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # JavaScript
    # -------------------------
    "cscript_js_execution": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript file execution via cscript",
        "indicators": ["cscript", ".js"],
        "base_confidence": 0.8,
    },

    "mshta_js_execution": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript execution via mshta with URL",
        "indicators": ["mshta", ".js", "http"],
        "base_confidence": 0.85,
    },

    "rundll32_js_execution": {
        "launcher": "rundll32",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript execution via rundll32",
        "indicators": ["rundll32", ".js"],
        "base_confidence": 0.8,
    },

    "cscript_js_encoded_command": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript encoded command execution",
        "indicators": ["cscript", "-e", "base64"],
        "base_confidence": 0.85,
    },

    "cscript_js_create_object": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript CreateObject usage",
        "indicators": ["cscript", "CreateObject", "ScriptControl"],
        "base_confidence": 0.8,
    },

    "cscript_js_eval": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript Eval method",
        "indicators": ["cscript", "Eval"],
        "base_confidence": 0.85,
    },

    "cscript_js_execute": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript Execute method",
        "indicators": ["cscript", "Execute"],
        "base_confidence": 0.8,
    },

    "cscript_js_run": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript Run method",
        "indicators": ["cscript", "Run"],
        "base_confidence": 0.8,
    },

    "cscript_js_from_base64": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript FromBase64String method",
        "indicators": ["cscript", "FromBase64String"],
        "base_confidence": 0.85,
    },

    "mshta_js_eval": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript Eval via mshta",
        "indicators": ["mshta", "Eval"],
        "base_confidence": 0.85,
    },

    "rundll32_js_eval": {
        "launcher": "rundll32",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript Eval via rundll32",
        "indicators": ["rundll32", "Eval"],
        "base_confidence": 0.85,
    },

    "cscript_js_encoded_command_chain": {
        "launcher": "cscript",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript encoded command with chaining",
        "indicators": ["cscript", "-e", "base64", "&&"],
        "base_confidence": 0.95,
    },

    "mshta_javascript": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "Inline JavaScript execution via mshta",
        "indicators": ["javascript:", "ActiveXObject"],
        "base_confidence": 0.9,
    },

    "rundll32_javascript": {
        "launcher": "rundll32",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript protocol execution via rundll32",
        "indicators": ["rundll32", "javascript:"],
        "base_confidence": 0.9,
    },

    "mshta_http_file": {
        "launcher": "mshta",
        "interpreter": "html",
        "rule_scope": "html",
        "behavior": "MSHTA loading HTA from HTTP",
        "indicators": ["mshta", ".hta", "http"],
        "base_confidence": 0.9,
    },

    "mshta_local_file": {
        "launcher": "mshta",
        "interpreter": "html",
        "rule_scope": "html",
        "behavior": "MSHTA loading HTA from local path",
        "indicators": ["mshta", ".hta", "users", "temp", "appdata"],
        "base_confidence": 0.85,
    },

    "mshta_vbscript_url": {
        "launcher": "mshta",
        "interpreter": "vbscript",
        "rule_scope": "vbscript",
        "behavior": "VBScript protocol execution via mshta",
        "indicators": ["mshta", "vbscript:"],
        "base_confidence": 0.9,
    },

    "mshta_about_url": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "About protocol execution via mshta",
        "indicators": ["mshta", "about:"],
        "base_confidence": 0.8,
    },

    "hta_application": {
        "launcher": "mshta",
        "interpreter": "html",
        "rule_scope": "html",
        "behavior": "HTA application declaration",
        "indicators": ["<hta:application>"],
        "base_confidence": 0.85,
    },

    "mshta_http_html_file": {
        "launcher": "mshta",
        "interpreter": "html",
        "rule_scope": "html",
        "behavior": "MSHTA loading HTML/PHP from HTTP",
        "indicators": ["mshta", "http", "html", "php", "asp", "jsp"],
        "base_confidence": 0.85,
    },

    "mshta_activeX": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "MSHTA ActiveX object creation",
        "indicators": ["mshta", "activexobject", "xmlhttp", "adodb.stream"],
        "base_confidence": 0.9,
    },

    "mshta_eval": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "MSHTA eval execution",
        "indicators": ["mshta", "eval", "atob", "chr", "execute"],
        "base_confidence": 0.9,
    },

    "mshta_chain_command": {
        "launcher": "cmd.exe",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "MSHTA command chaining",
        "indicators": ["cmd.exe", "powershell", "wscript", "rundll32", "mshta"],
        "base_confidence": 0.85,
    },

    "mshta_command": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "MSHTA generic command execution",
        "indicators": ["mshta"],
        "base_confidence": 0.6,
    },

    # -------------------------
    # System Binary Proxy Execution (T1218)
    # -------------------------
    "t1218_mshta_proxy": {
        "launcher": "mshta",
        "interpreter": "lolbin",
        "rule_scope": "lolbin",
        "behavior": "mshta.exe used as a proxy execution host",
        "indicators": ["mshta.exe", "mshta"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # Obfuscated Files or Information (T1027)
    # -------------------------
    "js_string_concat_obfuscation": {
        "launcher": "mshta",
        "interpreter": "javascript",
        "rule_scope": "javascript",
        "behavior": "JavaScript string concatenation obfuscation",
        "indicators": ["javascript:", "'+", "+'"],
        "base_confidence": 0.7,
    },

    # -------------------------
    # Lua
    # -------------------------
    "lua_oneliner_download": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua one-liner HTTP download",
        "indicators": ["lua", "-e", "http"],
        "base_confidence": 0.8,
    },

    "lua_loadstring_url": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua loadstring from HTTP",
        "indicators": ["lua", "loadstring", "http"],
        "base_confidence": 0.85,
    },

    "lua_require_socket_url": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua socket require with HTTP",
        "indicators": ["lua", "require", "socket", "http"],
        "base_confidence": 0.85,
    },

    "lua_os_execute_curl": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua os.execute curl download",
        "indicators": ["lua", "os.execute", "curl", "-O"],
        "base_confidence": 0.85,
    },

    "lua_os_execute_wget": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua os.execute wget",
        "indicators": ["lua", "os.execute", "wget", "http"],
        "base_confidence": 0.85,
    },

    "lua_base64_decode_loadstring": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua base64 decode to loadstring",
        "indicators": ["lua", "base64.decode", "loadstring"],
        "base_confidence": 0.9,
    },

    "lua_base64_decode_loadfile": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua base64 decode to loadfile",
        "indicators": ["lua", "base64.decode", "loadfile"],
        "base_confidence": 0.9,
    },

    "lua_io_popen_curl": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua io.popen curl download",
        "indicators": ["lua", "io.popen", "curl", "-O"],
        "base_confidence": 0.85,
    },

    "lua_io_popen_wget": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua io.popen wget",
        "indicators": ["lua", "io.popen", "wget", "http"],
        "base_confidence": 0.85,
    },

    "lua_download_and_execute": {
        "launcher": "lua",
        "interpreter": "lua",
        "rule_scope": "lua",
        "behavior": "Lua download and execute",
        "indicators": ["lua", "-e", "http", "&&"],
        "base_confidence": 0.9,
    },

    # -------------------------
    # Hypervisor CLI
    # -------------------------
    "hypervisor_cli_url_download": {
        "launcher": "hypervisor_cli",
        "interpreter": "hypervisor_cli",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI URL download",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "-c", "http"],
        "base_confidence": 0.8,
    },

    "hypervisor_cli_requests_download": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI requests download",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "requests", "get"],
        "base_confidence": 0.85,
    },

    "hypervisor_cli_base64_exec": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI base64 exec",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "exec", "base64"],
        "base_confidence": 0.9,
    },

    "hypervisor_cli_system_curl": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI os.system curl",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "system", "curl"],
        "base_confidence": 0.9,
    },

    "hypervisor_cli_subprocess_wget": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI subprocess wget",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "subprocess", "wget"],
        "base_confidence": 0.9,
    },

    "hypervisor_cli_nested_download": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI nested download",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "os.system", "http"],
        "base_confidence": 0.9,
    },

    "hypervisor_cli_download_execute": {
        "launcher": "hypervisor_cli",
        "interpreter": "python",
        "rule_scope": "hypervisor",
        "behavior": "Hypervisor CLI download and execute",
        "indicators": ["virsh", "VBoxManage", "qm", "xe", "govc", "http", "exec"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # Container CLI
    # -------------------------
    "container_cli_url_download": {
        "launcher": "container_cli",
        "interpreter": "container_cli",
        "rule_scope": "container",
        "behavior": "Container CLI URL download",
        "indicators": ["docker", "kubectl", "podman", "crictl", "-c", "http"],
        "base_confidence": 0.8,
    },

    "container_cli_requests_download": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI requests download",
        "indicators": ["docker", "kubectl", "podman", "crictl", "requests", "get"],
        "base_confidence": 0.85,
    },

    "container_cli_base64_exec": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI base64 exec",
        "indicators": ["docker", "kubectl", "podman", "crictl", "exec", "base64"],
        "base_confidence": 0.9,
    },

    "container_cli_system_curl": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI os.system curl",
        "indicators": ["docker", "kubectl", "podman", "crictl", "system", "curl"],
        "base_confidence": 0.9,
    },

    "container_cli_subprocess_wget": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI subprocess wget",
        "indicators": ["docker", "kubectl", "podman", "crictl", "subprocess", "wget"],
        "base_confidence": 0.9,
    },

    "container_cli_nested_download": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI nested download",
        "indicators": ["docker", "kubectl", "podman", "crictl", "os.system", "http"],
        "base_confidence": 0.9,
    },

    "container_cli_download_execute": {
        "launcher": "container_cli",
        "interpreter": "python",
        "rule_scope": "container",
        "behavior": "Container CLI download and execute",
        "indicators": ["docker", "kubectl", "podman", "crictl", "http", "exec"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # Network Device CLI - T1059.008
    # -------------------------
    "network_device_cli_wget": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI wget download",
        "indicators": ["ssh", "telnet", "wget", "http"],
        "base_confidence": 0.85,
    },

    "network_device_cli_curl": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI curl download",
        "indicators": ["ssh", "telnet", "curl", "-O", "http"],
        "base_confidence": 0.85,
    },

    "network_device_cli_tftp": {
        "launcher": "tftp",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI TFTP transfer",
        "indicators": ["tftp", "get", "put"],
        "base_confidence": 0.8,
    },

    "network_device_cli_certutil_download": {
        "launcher": "certutil",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI certutil download",
        "indicators": ["certutil", "-urlcache", "-f"],
        "base_confidence": 0.9,
    },

    "network_device_cli_bitsadmin_transfer": {
        "launcher": "bitsadmin",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI bitsadmin transfer",
        "indicators": ["bitsadmin", "/transfer"],
        "base_confidence": 0.85,
    },

    "network_device_cli_wmic_process_create": {
        "launcher": "wmic",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI WMI process creation",
        "indicators": ["wmic", "process", "call", "create"],
        "base_confidence": 0.85,
    },

    "network_device_cli_base64_decode": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI base64 decode to shell",
        "indicators": ["ssh", "telnet", "echo", "base64", "-d", "bash"],
        "base_confidence": 0.9,
    },

    "network_device_cli_perl_download": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI Perl download",
        "indicators": ["ssh", "telnet", "perl", "-e", "http"],
        "base_confidence": 0.85,
    },

    "network_device_cli_python_download": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI Python download",
        "indicators": ["ssh", "telnet", "python", "-c", "http"],
        "base_confidence": 0.85,
    },

    "network_device_cli_download_and_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI download and execute",
        "indicators": ["ssh", "telnet", "curl", "wget", "tftp", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_execute_command": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI interpreter execution",
        "indicators": ["ssh", "telnet", "bash", "sh", "perl", "python"],
        "base_confidence": 0.75,
    },

    "network_device_cli_base64_decode_chain": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI base64 decode with command chaining",
        "indicators": ["ssh", "telnet", "base64", "-d", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_tftp_download_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI TFTP download and execute",
        "indicators": ["ssh", "telnet", "tftp", "-g", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_perl_download_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI Perl download and execute",
        "indicators": ["ssh", "telnet", "perl", "-e", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_python_download_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI Python download and execute",
        "indicators": ["ssh", "telnet", "python", "-c", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_curl_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI curl download and execute",
        "indicators": ["ssh", "telnet", "curl", "-O", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_wget_execute": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI wget download and execute",
        "indicators": ["ssh", "telnet", "wget", "http", "&&"],
        "base_confidence": 0.95,
    },

    "network_device_cli_execute_chain_command": {
        "launcher": "ssh/telnet",
        "interpreter": "network_cli",
        "rule_scope": "network_device",
        "behavior": "Network Device CLI interpreter with command chaining",
        "indicators": ["ssh", "telnet", "bash", "sh", "perl", "python", "&&"],
        "base_confidence": 0.85,
    },

    # -------------------------
    # Cloud API - T1059.009
    # -------------------------
    "cloud_api_aws_lambda_invoke": {
        "launcher": "aws_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "AWS Lambda function invocation with HTTP payload",
        "indicators": ["aws", "lambda", "invoke", "--payload", "http"],
        "base_confidence": 0.85,
    },

    "cloud_api_azure_function_invoke": {
        "launcher": "az_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Azure Function invocation with HTTP data",
        "indicators": ["az", "functionapp", "function", "invoke", "--data", "http"],
        "base_confidence": 0.85,
    },

    "cloud_api_gcp_cloud_function_invoke": {
        "launcher": "gcloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "GCP Cloud Function invocation with HTTP data",
        "indicators": ["gcloud", "functions", "call", "--data", "http"],
        "base_confidence": 0.85,
    },

    "cloud_api_aws_s3_cp": {
        "launcher": "aws_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "AWS S3 file copy from HTTP",
        "indicators": ["aws", "s3", "cp", "http"],
        "base_confidence": 0.8,
    },

    "cloud_api_azure_storage_blob_download": {
        "launcher": "az_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Azure Storage blob download",
        "indicators": ["az", "storage", "blob", "download"],
        "base_confidence": 0.8,
    },

    "cloud_api_gcp_storage_cp": {
        "launcher": "gsutil",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "GCP Storage file copy",
        "indicators": ["gsutil", "cp", "gs://"],
        "base_confidence": 0.8,
    },

    "cloud_api_invoke_and_execute": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud function invoke and execute",
        "indicators": ["aws", "lambda", "az", "functionapp", "gcloud", "functions", "http", "&&"],
        "base_confidence": 0.95,
    },

    "cloud_api_storage_download_and_execute": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud storage download and execute",
        "indicators": ["aws", "s3", "az", "storage", "gsutil", "http", "&&"],
        "base_confidence": 0.95,
    },

    "cloud_api_invoke_command": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud function invocation",
        "indicators": ["aws", "lambda", "invoke", "az", "functionapp", "gcloud", "functions"],
        "base_confidence": 0.75,
    },

    "cloud_api_storage_download_command": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud storage download",
        "indicators": ["aws", "s3", "cp", "az", "storage", "blob", "gsutil", "http"],
        "base_confidence": 0.8,
    },

    "cloud_api_invoke_chain_command": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud function invoke with command chaining",
        "indicators": ["lambda", "invoke", "functionapp", "functions", "call", "http", "&&"],
        "base_confidence": 0.95,
    },

    "cloud_api_storage_download_chain_command": {
        "launcher": "cloud_cli",
        "interpreter": "cloud_api",
        "rule_scope": "cloud",
        "behavior": "Cloud storage download with command chaining",
        "indicators": ["s3", "cp", "storage", "blob", "gsutil", "http", "&&"],
        "base_confidence": 0.95,
    },

    # -------------------------
    # AutoHotkey & AutoIt - T1059.010
    # -------------------------
    "autohotkey_download_execute": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey download and execute",
        "indicators": ["AutoHotkey", "http", "&&", ".ahk"],
        "base_confidence": 0.9,
    },

    "autoit_download_execute": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt download and execute",
        "indicators": ["AutoIt3", "http", "&&", ".au3"],
        "base_confidence": 0.9,
    },

    "autohotkey_encoded_command": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey encoded command execution",
        "indicators": ["AutoHotkey", "-e", "base64"],
        "base_confidence": 0.85,
    },

    "autoit_encoded_command": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt encoded command execution",
        "indicators": ["AutoIt3", "-e", "base64"],
        "base_confidence": 0.85,
    },

    "autohotkey_run_script": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey script execution",
        "indicators": ["AutoHotkey", ".ahk"],
        "base_confidence": 0.75,
    },

    "autoit_run_script": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt script execution",
        "indicators": ["AutoIt3", ".au3"],
        "base_confidence": 0.75,
    },

    "autohotkey_download": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey HTTP download",
        "indicators": ["AutoHotkey", "http"],
        "base_confidence": 0.8,
    },

    "autoit_download": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt HTTP download",
        "indicators": ["AutoIt3", "http"],
        "base_confidence": 0.8,
    },

    "autohotkey_chain_command": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey script with command chaining",
        "indicators": ["AutoHotkey", ".ahk", "&&"],
        "base_confidence": 0.85,
    },

    "autoit_chain_command": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt script with command chaining",
        "indicators": ["AutoIt3", ".au3", "&&"],
        "base_confidence": 0.85,
    },

    "autohotkey_base64_decode": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey base64 decode",
        "indicators": ["AutoHotkey", "base64decode"],
        "base_confidence": 0.85,
    },

    "autoit_base64_decode": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt base64 decode",
        "indicators": ["AutoIt3", "Base64Decode"],
        "base_confidence": 0.85,
    },

    "autohotkey_download_base64_decode": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey HTTP download with base64 decode",
        "indicators": ["AutoHotkey", "http", "base64decode"],
        "base_confidence": 0.9,
    },

    "autoit_download_base64_decode": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt HTTP download with base64 decode",
        "indicators": ["AutoIt3", "http", "Base64Decode"],
        "base_confidence": 0.9,
    },

    "autohotkey_download_execute_chain": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey download, execute with chaining",
        "indicators": ["AutoHotkey", "http", ".ahk", "&&"],
        "base_confidence": 0.95,
    },

    "autoit_download_execute_chain": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt download, execute with chaining",
        "indicators": ["AutoIt3", "http", ".au3", "&&"],
        "base_confidence": 0.95,
    },

    "autohotkey_base64_decode_chain": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey base64 decode with command chaining",
        "indicators": ["AutoHotkey", "base64decode", "&&"],
        "base_confidence": 0.95,
    },

    "autoit_base64_decode_chain": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt base64 decode with command chaining",
        "indicators": ["AutoIt3", "Base64Decode", "&&"],
        "base_confidence": 0.95,
    },

    "autohotkey_encoded_command_chain": {
        "launcher": "AutoHotkey",
        "interpreter": "autohotkey",
        "rule_scope": "automation",
        "behavior": "AutoHotkey encoded command with chaining",
        "indicators": ["AutoHotkey", "-e", "base64", "&&"],
        "base_confidence": 0.95,
    },

    "autoit_encoded_command_chain": {
        "launcher": "AutoIt3",
        "interpreter": "autoit",
        "rule_scope": "automation",
        "behavior": "AutoIt encoded command with chaining",
        "indicators": ["AutoIt3", "-e", "base64", "&&"],
        "base_confidence": 0.95,
    },

}