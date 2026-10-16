
import re
import html
from urllib.parse import unquote

from attack_signatures import ATTACK_SIGNATURES


MAX_INPUT_LENGTH = 200_000
MAX_DECODE_PASSES = 2


COMPILED_RULES = []

for rule in ATTACK_SIGNATURES:
    compiled_pattern = re.compile(
        rule["pattern"],
        re.IGNORECASE
    )

    COMPILED_RULES.append({
        "name": rule["name"],
        "category": rule["category"],
        "severity": rule["severity"],
        "compiled_pattern": compiled_pattern,
    })


def normalize_input(text):
    """
    Decode common URL and HTML encodings before inspection.
    Limit decoding passes to reduce repeated-encoding abuse.
    """

    if not isinstance(text, str):
        return ""

    normalized = text[:MAX_INPUT_LENGTH]

    for _ in range(MAX_DECODE_PASSES):
        decoded = html.unescape(unquote(normalized))

        if decoded == normalized:
            break

        normalized = decoded

    return normalized


def detect_attacks(text):
    """
    Inspect input and return unique rule matches.

    Existing output fields are preserved:
    name, category, severity.

    Additional field:
    evidence - the matched input fragment.
    """

    if not isinstance(text, str) or not text:
        return []

    normalized_text = normalize_input(text)

    matches = []
    matched_rule_names = set()

    for rule in COMPILED_RULES:
        match = rule["compiled_pattern"].search(normalized_text)

        if match:
            rule_name = rule["name"]

            # Avoid duplicate results if a rule name is repeated.
            if rule_name in matched_rule_names:
                continue

            matched_rule_names.add(rule_name)

            matches.append({
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "evidence": match.group(0)[:200],
            })

    return matches

