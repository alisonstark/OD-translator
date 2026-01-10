HEURISTIC_PATTERNS = {

        # Design a few GENERAL patterns for spotting powershell suspicious code execution using command patterns for technique T1059:
        "T1059.001": [

        r"(?:powershell|pwsh)(?:\.exe)?\s+.*\(New-Object\s+Net\.WebClient\)\.(DownloadString|DownloadData)\(", # DownloadString or DownloadData method
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*\[Reflection\.Assembly\]::Load\(", # Reflection Assembly Load
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Add-Type\s+-TypeDefinition", # Add-Type with TypeDefinition
        r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]n(codedCommand)?\s+[A-Za-z0-9+/=]{20,}", # EncodedCommand with base64 string
        r"(?:powershell|pwsh)(?:\.exe)?\s+-[eE]x(ecute)?\s+\$[a-zA-Z0-9_]+\s*=\s*(iwr|Invoke-WebRequest|wget|curl|irm)\s+http[s]?://", # Execute with variable assignment from web request
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://", # Web request commands
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+http[s]?://.*\|\s*(iex|Invoke-Expression)", # Web request piped to expression
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*(Invoke-WebRequest|Invoke-RestMethod|iwr|irm).*\|\s*(iex|Invoke-Expression)", # Any web request piped to expression
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*New-Object\s+Net\.WebClient.*DownloadString\s*\(", # New-Object WebClient DownloadString
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Net\.WebClient.*DownloadFile\s*\(", # WebClient DownloadFile
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*System\.Net\.WebRequest.*GetResponse\s*\(", # WebRequest GetResponse
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Add-Type\s+.*DllImport", # Add-Type with DllImport
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Reflection\.Assembly::Load", # Reflection Assembly Load
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*FromBase64String\s*\(", # FromBase64String method
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Invoke-Command\s+-ScriptBlock", # Invoke-Command with ScriptBlock
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*Start-Process\s+.*-ArgumentList", # Start-Process with ArgumentList
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*-ExecutionPolicy\s+Bypass", # ExecutionPolicy Bypass
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*-NoProfile", # NoProfile flag
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*-WindowStyle\s+Hidden" # Hidden WindowStyle

        ],
        
        # Design a few GENERAL patterns for spotting Windows Command Shell suspicious code execution using command patterns for technique T1059:
        "T1059.003": [
            r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+http[s]?://", 
            r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+", 
            r"cmd\.exe\s+/c\s+powershell\s+.*-e\s+[A-Za-z0-9+/=]{20,}", 
            r"cmd\.exe\s+/c\s+wmic\s+process\s+call\s+create\s+", 
            r"cmd\.exe\s+/c\s+start\s+.*http[s]?://",
            r"cmd\.exe\s+/c\s+ftp\s+-s:", 
            r"cmd\.exe\s+/c\s+regsvr32\s+/s\s+/n\s+/u\s+/i:http[s]?://", 
            r"cmd\.exe\s+/c\s+mshta\s+http[s]?://", 
            r"cmd\.exe\s+/c\s+rundll32\s+url.dll,FileProtocolHandler\s+http[s]?://",

            r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://", # certutil download from URL
            r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://", # bitsadmin transfer command
            r"cmd\.exe\s+/c\s+powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", # powershell encoded command
            r"cmd\.exe\s+/c\s+wmic\s+process\s+call\s+create\s+", # wmic process create
            r"cmd\.exe\s+/c\s+start\s+.*http[s]?://.*\.(exe|dll|js|vbs|hta|ps1|bat|cmd)", # start command with URL
            r"cmd\.exe\s+/c\s+ftp\s+-s:", # ftp script execution
            r"cmd\.exe\s+/c\s+regsvr32\s+/s\s+/n\s+/u\s+/i:http[s]?://", # regsvr32 with URL
            r"cmd\.exe\s+/c\s+mshta\s+http[s]?://", # mshta with URL
            r"cmd\.exe\s+/c\s+rundll32\s+url\.dll,FileProtocolHandler\s+http[s]?://",  # rundll32 with URL

            # Other high-confidence variants for download and execute
            r"cmd\.exe\s+/c\s+certutil\s+-urlcache\s+-split\s+-f\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", # certutil download and execute
            r"cmd\.exe\s+/c\s+bitsadmin\s+/transfer\s+\S+\s+http[s]?://.*\s+&&\s+(\S+\.exe|\S+\.dll|\S+\.bat|\S+\.cmd|\S+\.ps1)", # bitsadmin download and execute
            r"cmd\.exe\s+/c\s+(powershell|pwsh|cmd|wscript|cscript)\.exe", # Shell-to-shell pivot (critical)
            r"cmd\.exe\s+/c\s+schtasks\s+/create", # Scheduled task creation (optional but strong)
        ],
        # Other techniques can be added here

}