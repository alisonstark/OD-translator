from odt.core.detector import detect_t1059, detect_t1027, detect_t1218
from odt.core.output import build_output
from odt.core.parser import normalize_command


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
