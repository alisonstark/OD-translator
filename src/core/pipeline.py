from core.decoder import decode_command
from core.detector import detect_technique
from core.mitre import get_attackcti_cache
from core.output import build_output
from core.parser import normalize_command

# Main translation pipeline that takes a command string and returns a structured output of MITRE ATT&CK technique mappings.
# It normalizes the command, optionally decodes obfuscation, detects all supported techniques by default,
# and builds the final output dictionary.
ALL_TECHNIQUES = ["T1059", "T1218", "T1027", "T1105", "T1071", "T1543", "T1055"]


def translate_command(
    command: str,
    refresh_mitre: bool = False,
    decode: bool = False,
) -> dict:
    # Warm MITRE cache because all techniques are always analyzed.
    get_attackcti_cache(refresh=refresh_mitre)
    
    # Optionally decode obfuscated commands
    decode_info = None
    analysis_command = command
    if decode:
        decode_result = decode_command(command)
        if decode_result['was_decoded']:
            decode_info = decode_result
            analysis_command = decode_result['decoded']
    
    normalized = normalize_command(analysis_command)
    detections = []
    for technique_id in ALL_TECHNIQUES:
        detections.extend(
            detect_technique(normalized, technique_id, refresh_mitre=refresh_mitre)
        )
    
    output = build_output(command, normalized, detections)
    
    # Add decode information if decoding was attempted and successful
    if decode_info:
        output['decode_info'] = {
            'encodings_detected': decode_info['encodings_detected'],
            'encodings_decoded': decode_info['encodings_decoded'],
            'decoded_command': decode_info['decoded']
        }
    
    return output
