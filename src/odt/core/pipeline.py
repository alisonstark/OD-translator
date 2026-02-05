from odt.core.detector import detect_t1059
from odt.core.output import build_output
from odt.core.parser import normalize_command


def translate_command(command: str, refresh_mitre: bool = False) -> dict:
    normalized = normalize_command(command)
    detections = detect_t1059(normalized, refresh_mitre=refresh_mitre)
    return build_output(command, normalized, detections)
