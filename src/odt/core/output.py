from typing import Any, Dict, List


def build_output(
    original_command: str,
    normalized_command: str,
    detections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "input_command": original_command,
        "normalized_command": normalized_command,
        "detections": detections,
    }
