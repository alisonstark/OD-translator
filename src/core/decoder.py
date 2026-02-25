"""
Decoder module for handling common obfuscation/encoding techniques in offensive commands.

This module implements a hybrid approach:
1. Detect obfuscation patterns (for T1027 mapping)
2. Optionally decode them for better technique detection
"""

import base64
import re
from typing import Dict, List, Tuple
from urllib.parse import unquote


def detect_encoding_types(command: str) -> List[str]:
    """
    Detect which encoding/obfuscation types are present in the command.
    
    Returns a list of encoding types found (e.g., ['base64', 'fromcharcode'])
    """
    encodings = []
    command_lower = command.lower()
    
    # PowerShell base64
    if re.search(r'-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}', command, re.IGNORECASE):
        encodings.append('powershell_base64')
    
    # JavaScript atob()
    if 'atob(' in command_lower:
        encodings.append('javascript_atob')
    
    # JavaScript/VBScript String.fromCharCode or chr()
    if 'fromcharcode(' in command_lower or 'chr(' in command_lower:
        encodings.append('charcode')
    
    # URL encoding
    if re.search(r'%[0-9A-F]{2}', command, re.IGNORECASE):
        encodings.append('url_encoding')
    
    # Unicode escapes
    if re.search(r'\\u[0-9a-f]{4}', command, re.IGNORECASE):
        encodings.append('unicode_escape')
    
    # Hex encoding
    if re.search(r'0x[0-9a-f]{2}', command, re.IGNORECASE):
        encodings.append('hex')
    
    return encodings


def decode_powershell_base64(command: str) -> Tuple[str, bool]:
    """
    Decode PowerShell -encodedCommand base64 strings.
    
    Returns: (decoded_command, was_decoded)
    """
    # Match PowerShell encoded command pattern
    pattern = r'(-e(?:nc|ncodedcommand)?)\s+([A-Za-z0-9+/=]{20,})'
    match = re.search(pattern, command, re.IGNORECASE)
    
    if not match:
        return command, False
    
    try:
        encoded_part = match.group(2)
        # PowerShell uses UTF-16LE encoding
        decoded_bytes = base64.b64decode(encoded_part)
        decoded_str = decoded_bytes.decode('utf-16-le', errors='ignore')
        
        # Replace the encoded portion with decoded version
        result = command[:match.start()] + decoded_str + command[match.end():]
        return result, True
    except Exception:
        return command, False


def decode_javascript_atob(command: str) -> Tuple[str, bool]:
    """
    Decode JavaScript atob() base64 strings.
    
    Returns: (decoded_command, was_decoded)
    """
    # Match atob('base64string')
    pattern = r'atob\s*\(\s*[\'"]([A-Za-z0-9+/=]+)[\'"]\s*\)'
    matches = re.finditer(pattern, command, re.IGNORECASE)
    
    decoded_command = command
    was_decoded = False
    
    for match in matches:
        try:
            encoded_part = match.group(1)
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            # Replace atob('...') with the decoded string
            decoded_command = decoded_command.replace(match.group(0), f'"{decoded_str}"')
            was_decoded = True
        except Exception:
            continue
    
    return decoded_command, was_decoded


def decode_fromcharcode(command: str) -> Tuple[str, bool]:
    """
    Decode JavaScript String.fromCharCode() or VBScript Chr() encodings.
    
    Returns: (decoded_command, was_decoded)
    """
    # Match String.fromCharCode(118,97,114,...) or chr(118)
    pattern = r'(?:String\.)?fromCharCode\s*\(\s*([\d,\s]+)\s*\)'
    matches = re.finditer(pattern, command, re.IGNORECASE)
    
    decoded_command = command
    was_decoded = False
    
    for match in matches:
        try:
            # Extract character codes
            char_codes = [int(code.strip()) for code in match.group(1).split(',')]
            decoded_str = ''.join(chr(code) for code in char_codes)
            
            # Replace fromCharCode(...) with the decoded string
            decoded_command = decoded_command.replace(match.group(0), f'"{decoded_str}"')
            was_decoded = True
        except Exception:
            continue
    
    return decoded_command, was_decoded


def decode_url_encoding(command: str) -> Tuple[str, bool]:
    """
    Decode URL-encoded strings.
    
    Returns: (decoded_command, was_decoded)
    """
    try:
        decoded = unquote(command)
        was_decoded = decoded != command
        return decoded, was_decoded
    except Exception:
        return command, False


def decode_command(command: str, encoding_types: List[str] = None) -> Dict[str, object]:
    """
    Attempt to decode a command using multiple strategies.
    
    Args:
        command: The potentially encoded command
        encoding_types: List of encoding types to try (None = auto-detect)
    
    Returns:
        {
            'original': original command,
            'decoded': decoded command,
            'encodings_detected': list of detected encodings,
            'encodings_decoded': list of successfully decoded encodings,
            'was_decoded': boolean indicating if any decoding occurred
        }
    """
    if encoding_types is None:
        encoding_types = detect_encoding_types(command)
    
    result = {
        'original': command,
        'decoded': command,
        'encodings_detected': encoding_types,
        'encodings_decoded': [],
        'was_decoded': False
    }
    
    current = command
    
    # Try each decoder in sequence
    if 'powershell_base64' in encoding_types:
        current, decoded = decode_powershell_base64(current)
        if decoded:
            result['encodings_decoded'].append('powershell_base64')
            result['was_decoded'] = True
    
    if 'javascript_atob' in encoding_types:
        current, decoded = decode_javascript_atob(current)
        if decoded:
            result['encodings_decoded'].append('javascript_atob')
            result['was_decoded'] = True
    
    if 'charcode' in encoding_types:
        current, decoded = decode_fromcharcode(current)
        if decoded:
            result['encodings_decoded'].append('charcode')
            result['was_decoded'] = True
    
    if 'url_encoding' in encoding_types:
        current, decoded = decode_url_encoding(current)
        if decoded:
            result['encodings_decoded'].append('url_encoding')
            result['was_decoded'] = True
    
    result['decoded'] = current
    return result
