from core.detector import detect_secondary_techniques, detect_t1059
from core.mitre import get_attackcti_cache
from core.output import build_output
from core.parser import normalize_command

# Main translation pipeline that takes a command string and returns a structured output of MITRE ATT&CK technique mappings.
# It normalizes the command, detects techniques (T1059 by default, with optional secondary techniques), 
# and builds the final output dictionary.
def translate_command(
    command: str,
    refresh_mitre: bool = False,
    include_secondary_techniques: bool = False,
) -> dict:
    if include_secondary_techniques:
        get_attackcti_cache(refresh=refresh_mitre)
    normalized = normalize_command(command)
    detections = detect_t1059(normalized, refresh_mitre=refresh_mitre)
    if include_secondary_techniques:
        detections = detect_secondary_techniques(
            normalized,
            primary_technique="T1059",
            refresh_mitre=refresh_mitre,
        ) + detections
    return build_output(command, normalized, detections)
