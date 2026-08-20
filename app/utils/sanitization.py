import re
from typing import Any, Dict

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"(?i)key"),
    re.compile(r"(?i)token"),
    re.compile(r"(?i)password"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)auth"),
    re.compile(r"(?i)credential"),
    re.compile(r"(?i)bearer"),
    re.compile(r"(?i)signature"),
    re.compile(r"(?i)privateKey"),
    re.compile(r"(?i)apiKey")
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all|previous)\s+instructions"),
    re.compile(r"(?i)drop\s+table"),
    re.compile(r"(?i)<script"),
    re.compile(r"(?i)system:|assistant:|<\|im_start\|>")
]

def sanitize_parameters(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes sensitive values in parameters dict.
    Returns a copy of the dictionary with redacted secrets and malicious scripts.
    Does not modify the original dictionary.
    """
    if not isinstance(parameters, dict):
        return {}

    sanitized = {}
    for k, v in parameters.items():
        # Check if the key indicates a sensitive field
        is_sensitive = False
        for pattern in SENSITIVE_KEY_PATTERNS:
            if pattern.search(k):
                is_sensitive = True
                break

        if is_sensitive:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            # Also redact values matching injection/malicious patterns
            is_injection = False
            for val_pattern in PROMPT_INJECTION_PATTERNS:
                if val_pattern.search(v):
                    is_injection = True
                    break
            if is_injection:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = v
        elif isinstance(v, dict):
            # Recursively check dictionaries
            sanitized[k] = sanitize_parameters(v)
        elif isinstance(v, list):
            # Check list items recursively
            sanitized[k] = [
                sanitize_parameters(item) if isinstance(item, dict)
                else ("[REDACTED]" if isinstance(item, str) and any(pat.search(item) for pat in PROMPT_INJECTION_PATTERNS) else item)
                for item in v
            ]
        else:
            sanitized[k] = v
            
    return sanitized
