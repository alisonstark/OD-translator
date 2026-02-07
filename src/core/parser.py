import re

# This module provides functions for normalizing command strings 
# and detecting specific MITRE ATT&CK techniques based on predefined rules and patterns.

# The normalization process standardizes the command format, 
# while the detection functions analyze the command against known indicators to identify potential technique mappings.
def normalize_command(command: str) -> str:
    normalized = command.strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized
