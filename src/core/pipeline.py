from core.detector import detect_t1059, detect_t1027, detect_t1218
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
    normalized = normalize_command(command)
    detections = detect_t1059(normalized, refresh_mitre=refresh_mitre)
    if include_secondary_techniques:
        detections = detect_t1218(normalized) + detect_t1027(normalized) + detections
    return build_output(command, normalized, detections)
