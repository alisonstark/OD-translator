import re


def normalize_command(command: str) -> str:
    normalized = command.strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized
