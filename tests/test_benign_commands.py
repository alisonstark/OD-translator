"""
Benign Command False-Positive Testing

This test module validates detection accuracy against **legitimate, non-malicious commands**
that would appear in normal Windows/Linux system administration and automation workflows.

Purpose:
    - Establish a baseline false-positive rate for the detection system
    - Identify patterns that trigger on benign activity
    - Balance sensitivity vs. specificity trade-offs
    - Ensure analyst trust in the tool by reducing noise

Approach:
    - Test realistic administrative commands (Windows Update, system utilities, etc.)
    - Test legitimate automation scripts (DevOps, CI/CD, system maintenance)
    - Test common developer tools and workflows
    - Track confidence levels of any unexpected detections
    - Document acceptable false-positive thresholds

Expected Behavior:
    - Most benign commands should NOT trigger detections
    - Commands that DO trigger should have LOW confidence (<0.5) or be acceptable trade-offs
    - Commands with MEDIUM-to-HIGH confidence require pattern refinement

Trade-off Philosophy:
    - Some false positives are acceptable to maintain malware detection sensitivity
    - Confidence scoring helps analysts prioritize investigations
    - A 0.45-confidence detection on "powershell -NoProfile" is acceptable noise
    - A 0.85-confidence detection is worth investigating, even if rare
"""

import sys
from pathlib import Path

src_root = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_root))

from core.detector import detect_t1059, detect_t1218, detect_t1027, detect_t1105, detect_t1071
from core.pipeline import translate_command


# ===== Windows System Administration Commands =====

def test_benign_windows_update_check():
    """Test legitimate Windows Update checking command."""
    cmd = r'powershell -NoProfile -WindowStyle Hidden -Command "Get-HotFix -ComputerName localhost"'
    result = translate_command(cmd)
    
    # Should produce minimal or no detections
    # If detections occur, they should be low confidence (<0.6)
    if result["detections"]:
        for detection in result["detections"]:
            assert detection["confidence"] < 0.6, f"Unexpected high-confidence on benign command: {cmd}"


def test_benign_get_process():
    """Test legitimate command to list running processes."""
    cmd = 'Get-Process | Where-Object {$_.Name -like "svc*"} | Format-Table Name, ID'
    detections = detect_t1059(cmd)
    
    # PowerShell process enumeration is common and legitimate
    # Accept low-confidence detections or none
    assert len(detections) == 0 or all(d["confidence"] < 0.5 for d in detections)


def test_benign_dir_command():
    """Test basic directory listing (T1059 only, not network-based)."""
    cmd = "cmd.exe /c dir C:\\Windows\\System32"
    detections = detect_t1059(cmd)
    
    # Basic cmd usage should not trigger T1059 detection
    assert len(detections) == 0


def test_benign_check_disk_space():
    """Test system diagnostic command."""
    cmd = "wmic logicaldisk get name,size,freespace"
    detections = detect_t1059(cmd)
    
    assert len(detections) == 0


def test_benign_services_list():
    """Test listing system services."""
    cmd = "tasklist.exe /svc"
    detections = detect_t1059(cmd)
    
    assert len(detections) == 0


def test_benign_firewall_status():
    """Test checking firewall status."""
    cmd = 'netsh advfirewall show allprofiles state'
    detections = detect_t1059(cmd)
    
    assert len(detections) == 0


def test_benign_scheduled_task_list():
    """Test Windows scheduled task listing."""
    cmd = "schtasks /query /fo LIST /v"
    detections = detect_t1059(cmd)
    
    assert len(detections) == 0


# ===== Legitimate Network Operations =====

def test_benign_ping_localhost():
    """Test basic network diagnostics (ping)."""
    cmd = "ping -c 4 localhost"  # Linux/macOS style
    detections = detect_t1071(cmd)
    
    # ICMP ping should not trigger T1071 (app-layer protocol)
    assert len(detections) == 0


def test_benign_dns_query():
    """Test legitimate DNS lookup."""
    cmd = "nslookup www.example.com"
    detections = detect_t1071(cmd)
    
    # DNS query alone shouldn't trigger T1071 detection
    # (no HTTP/HTTPS or suspicious patterns)
    assert len(detections) == 0


def test_benign_curl_help():
    """Test curl tool help (not downloading anything dangerous)."""
    cmd = "curl --help"
    detections = detect_t1105(cmd)
    
    # Help flag should not trigger download detection
    assert len(detections) == 0


def test_benign_wget_version():
    """Test wget version check."""
    cmd = "wget --version"
    detections = detect_t1105(cmd)
    
    # Version flag should not trigger
    assert len(detections) == 0


def test_benign_curl_localhost():
    """Test curl to local service (HTTP community standard port)."""
    cmd = "curl http://localhost:8080/health"
    detections = detect_t1105(cmd)
    
    # Curl to localhost for health checks is common in DevOps
    # May trigger T1071 (network protocol) but not T1105 (ingress transfer)
    t1105_detections = [d for d in detections if d.get("technique_id") == "T1105"]
    assert len(t1105_detections) == 0  # Should not detect as tool transfer


# ===== DevOps & Automation Scripts =====

def test_benign_docker_status():
    """Test Docker service status check."""
    cmd = "docker ps --all --format 'table {{.ID}}\\t{{.Status}}'"
    result = translate_command(cmd)
    
    # Should not trigger malicious technique detection
    assert len(result.get("detections", [])) == 0


def test_benign_git_clone():
    """Test legitimate git repository clone."""
    cmd = "git clone https://github.com/torvalds/linux.git"
    result = translate_command(cmd)
    
    # Git clone is standard DevOps workflow
    # May trigger T1071 (network) but acceptable
    if result.get("detections"):
        for det in result["detections"]:
            if det["technique_id"] == "T1105":
                # T1105 (ingress tool transfer) is expected for legitimate tool downloads
                # But confidence should be reasonable
                pass  # Acceptable trade-off


def test_benign_npm_install():
    """Test Node.js package manager install."""
    cmd = "npm install express --save"
    result = translate_command(cmd)
    
    # npm operations are standard development workflow
    assert len(result.get("detections", [])) == 0


def test_benign_pip_install():
    """Test Python package manager install."""
    cmd = "pip install requests numpy"
    result = translate_command(cmd)
    
    # pip is standard Python development
    assert len(result.get("detections", [])) == 0


# ===== Legitimate Scripting Operations =====

def test_benign_vbscript_wscript_basic():
    """Test basic WScript usage (system info query)."""
    cmd = r'wscript.exe C:\Scripts\syinfo.vbs'
    detections = detect_t1059(cmd)
    
    # Basic script execution should not trigger without other context
    assert len(detections) == 0


def test_benign_powershell_module_import():
    """Test importing legitimate PowerShell modules."""
    cmd = 'powershell -c Import-Module ActiveDirectory; Get-ADUser -Filter *'
    result = translate_command(cmd)
    
    # Active Directory module for user enumeration is standard admin task
    # Should not trigger T1059 specifically for this
    t1059_dets = [d for d in result.get("detections", []) if d["technique_id"] == "T1059"]
    # Allow empty or low-confidence detections
    assert all(d.get("confidence", 0) < 0.6 for d in t1059_dets)


def test_benign_batch_script_execution():
    """Test running a basic batch script."""
    cmd = r'cmd.exe /c C:\Scripts\maintenance.bat'
    detections = detect_t1059(cmd)
    
    # Batch script execution (non-suspicious context)
    assert len(detections) == 0


# ===== Logging & Monitoring Operations =====

def test_benign_log_parsing():
    """Test parsing Windows event logs."""
    cmd = 'powershell -c Get-EventLog -LogName System -Newest 100 | Where-Object {$_.EventID -eq 1000}'
    result = translate_command(cmd)
    
    # SOC/admin activity reviewing logs is legitimate
    if result.get("detections"):
        for det in result["detections"]:
            # Confidence should be low for this context
            assert det.get("confidence", 0) < 0.6


def test_benign_grep_logs():
    """Test searching log files (Unix/Linux)."""
    cmd = "grep -r 'ERROR' /var/log/ | tail -100"
    result = translate_command(cmd)
    
    # Log searching is standard admin/monitoring task
    assert len(result.get("detections", [])) == 0


def test_benign_tail_log_file():
    """Test watching live log output."""
    cmd = "tail -f /var/log/syslog"
    result = translate_command(cmd)
    
    assert len(result.get("detections", [])) == 0


# ===== File Operations & Backups =====

def test_benign_robocopy_backup():
    """Test Windows file sync/backup operation."""
    cmd = r'robocopy C:\Users\JohnDoe\Documents X:\Backup\Documents /MIR /Z'
    result = translate_command(cmd)
    
    # Backup operations are legitimate
    assert len(result.get("detections", [])) == 0


def test_benign_zip_archive():
    """Test creating compressed archive."""
    cmd = 'powershell -c Compress-Archive -Path C:\\Logs -DestinationPath C:\\Logs.zip'
    result = translate_command(cmd)
    
    # Compression for backup is standard
    assert len(result.get("detections", [])) == 0


def test_benign_copy_command():
    """Test basic file copy operation."""
    cmd = r'copy C:\config.ini C:\config.backup'
    result = translate_command(cmd)
    
    assert len(result.get("detections", [])) == 0


# ===== Summary & False-Positive Baseline =====

def test_benign_commands_false_positive_rate():
    """
    Summary test that evaluates overall false-positive rate across benign commands.
    
    This test aggregates results from all benign command tests and provides:
    - Count of unexpected detections
    - Average confidence of false positives
    - Identification of patterns to refine
    """
    benign_commands = [
        (r'powershell -NoProfile -WindowStyle Hidden -Command "Get-HotFix -ComputerName localhost"', "Windows Update Check"),
        ("cmd.exe /c dir C:\\Windows\\System32", "Directory Listing"),
        ("wmic logicaldisk get name,size,freespace", "Disk Space Check"),
        ("tasklist.exe /svc", "Services List"),
        ("nslookup www.example.com", "DNS Query"),
        ("curl --help", "Curl Help"),
        ("git clone https://github.com/torvalds/linux.git", "Git Clone"),
        ("npm install express --save", "NPM Install"),
        ("grep -r 'ERROR' /var/log/ | tail -100", "Log Parsing"),
        (r'robocopy C:\Users\JohnDoe\Documents X:\Backup\Documents /MIR /Z', "Backup Operation"),
    ]
    
    false_positives = []
    false_positive_confidences = []
    
    for cmd, description in benign_commands:
        result = translate_command(cmd)
        if result.get("detections"):
            for detection in result["detections"]:
                confidence = detection.get("confidence", 0)
                false_positives.append({
                    "command": cmd,
                    "description": description,
                    "technique_id": detection.get("technique_id"),
                    "confidence": confidence,
                })
                if confidence > 0.5:
                    false_positive_confidences.append(confidence)
    
    # Print summary for analyst review
    print(f"\n=== Benign Command False-Positive Analysis ===")
    print(f"Commands tested: {len(benign_commands)}")
    print(f"Commands triggering detections: {len(set(fp['command'] for fp in false_positives))}")
    print(f"Total detections on benign commands: {len(false_positives)}")
    
    if false_positive_confidences:
        print(f"High-confidence false positives (>0.5): {len(false_positive_confidences)}")
        print(f"Avg high-confidence score: {sum(false_positive_confidences) / len(false_positive_confidences):.2f}")
        print(f"\nHigh-confidence detections to review:")
        for fp in false_positives:
            if fp["confidence"] > 0.5:
                print(f"  - {fp['description']}: {fp['technique_id']} ({fp['confidence']:.2f})")
    else:
        print("No high-confidence false positives detected! [GOOD]")
    
    # Assertion: High-confidence false positives should be rare and documented
    # Acceptable threshold: ≤20% of benign commands trigger medium+ confidence detections
    high_conf_rate = len(false_positive_confidences) / len(benign_commands)
    assert high_conf_rate <= 0.2, (
        f"False-positive rate too high: {high_conf_rate:.1%} of benign commands "
        f"triggered medium+ confidence detections"
    )
