# =========================
# Interpreter Capability Indicators
# =========================

INTERPRETER_KEY_MAP = {
    "powershell": "POWERSHELL_001_INDICATORS",
    "applescript": "APPLESCRIPT_002_INDICATORS",
    "cmd": "CMD_003_INDICATORS",
    "bash": "UNIX_SHELL_004_INDICATORS",
    "vbscript": "VISUAL_BASIC_005_INDICATORS",
    "python": "PYTHON_006_INDICATORS",
    "javascript": "JAVA_SCRIPT_007_INDICATORS",
    "network_cli": "NETWORK_DEVICE_008_INDICATORS",
    "cloud_api": "CLOUD_API_009_INDICATORS",
    "autohotkey": "AUTOHOTIT_010_INDICATORS",
    "autoit": "AUTOHOTIT_010_INDICATORS",
    "lua": "LUA_011_INDICATORS",
    "hypervisor_cli": "HYPER_V_012_INDICATORS",
    "container_cli": "CONTAINER_013_INDICATORS",
}

INTERPRETER_INDICATORS = {

    "POWERSHELL_001_INDICATORS": {
        "network_retrieval": (
            "downloadstring",
            "downloaddata",
            "invoke-webrequest",
            "invoke-restmethod",
            " iwr ",
            " irm ",
        ),
        "obfuscation": (
            "frombase64string",
        ),
        "dynamic_code": (
            "add-type",
            "reflection.assembly",
        )
    },

    "APPLESCRIPT_002_INDICATORS": {
        "interpreter_control": (
            "tell application",
            "osascript",
        ),
        "shell_execution": (
            "do shell script",
        ),
        "user_interaction": (
            "display dialog",
            "activate",
        ),
        "clipboard_manipulation": (
            "set the clipboard to",
        ),
    }, 


    "CMD_003_INDICATORS": {
        "file_download": (
            "certutil",
            "bitsadmin",
            "ftp ",
        ),
        "proxy_execution": (
            "mshta",
            "rundll32",
            "regsvr32",
        ),
        "system_discovery": (
            "wmic",
        ),
    },


    "UNIX_SHELL_004_INDICATORS": {
        "file_download": (
            "curl ",
            "wget ",
            "fetch ",
            "tftp ",
        ),
        "text_browser_fetch": (
            "lynx ",
            "links ",
        ),
    },


    "VISUAL_BASIC_005_INDICATORS": {
        "filesystem_access": (
            "createobject(\"scripting.filesystemobject\")",
        ),
        "command_execution": (
            "wscript.shell",
        ),
        "network_communication": (
            "xmlhttp",
            "adodb.stream",
        ),
        "system_management": (
            "getobject(\"winmgmts:\")",
        ),
    },


    "PYTHON_006_INDICATORS": {
        "process_execution": (
            "import subprocess",
        ),
        "network_communication": (
            "import socket",
            "import urllib",
            "import requests",
        ),
        "dynamic_execution": (
            "exec(",
            "eval(",
        ),
    },


    "JAVA_SCRIPT_007_INDICATORS": {
        "network_communication": (
            "xmlhttprequest",
            "http.open(",
            "http.send(",
        ),
        "activex_execution": (
            "wscript.createobject(",
            "activexobject(",
        ),
    },


    "NETWORK_DEVICE_008_INDICATORS": {
        "remote_access": (
            "ssh ",
            "telnet ",
        ),
        "network_management": (
            "snmpget",
            "snmpset",
            "snmpwalk",
        ),
    },


    "CLOUD_API_009_INDICATORS": {
        "cloud_resource_management": (
            "aws s3",
            "aws ec2",
            "gcloud compute",
            "az vm",
        ),
    },


    "AUTOHOTIT_010_INDICATORS": {
        "user_simulation": (
            "sendinput",
            "click ",
        ),
        "execution_flow_control": (
            "sleep ",
            "run ",
        ),
        "window_control": (
            "winactivate",
        ),
    },


    "LUA_011_INDICATORS": {
        "network_communication": (
            "http.request",
            "socket.http",
            "ssl.https",
        ),
        "process_execution": (
            "os.execute",
            "io.popen",
        ),
        "dynamic_execution": (
            "loadstring",
        ),
    },


    "HYPER_V_012_INDICATORS": {
        "virtualization_management": (
            "vmconnect.exe",
            "vmwp.exe",
            "vmswitch.exe",
            "hyperv",
        ),
    },


    "CONTAINER_013_INDICATORS": {
        "container_execution": (
            "docker run",
            "podman run",
        ),
        "container_orchestration": (
            "kubectl exec",
        ),
        "container_runtime": (
            "containerd",
        ),
    }
}
