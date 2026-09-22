import re


ALLOWED_CATEGORIES = {
    "SAFE",
    "TOXIC",
    "HARASSMENT",
    "THREAT",
    "SCAM",
    "PHISHING",
    "SPAM",
    "VOLATILE",
    "CONCERN",
    "ADULT",
}

ALLOWED_ACTIONS = {
    "ALLOW",
    "REVIEW",
    "BLOCK",
    "ESCALATE",
}

LANGUAGE_PATTERN = r"^[a-zA-Z]{2,3}(?:-[A-Za-z]{2,4})?$"


def _clean_language(value) -> str:
    if not isinstance(value, str):
        return ""

    language = value.strip().lower()

    if re.match(LANGUAGE_PATTERN, language):
        return language[:8]

    return ""


def _clamp(value, low: float, high: float, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default

    return max(low, min(high, number))


def _as_string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, str)]


def normalize(raw: dict) -> dict | None:
    """Validate and clamp an AI response into a safe structured shape.

    Returns None when the payload is unusable so the caller can fall back to
    deterministic analysis. Scores are clamped, categories/actions are
    whitelisted, and nothing from the model is trusted as a directive."""
    if not isinstance(raw, dict):
        return None

    categories = [
        cat.upper()
        for cat in _as_string_list(raw.get("categories"))
        if cat.upper() in ALLOWED_CATEGORIES
    ]

    action = str(raw.get("suggested_action", "")).upper()

    if action not in ALLOWED_ACTIONS:
        action = ""

    if not categories and not action:
        toxicity = raw.get("toxicity")
        spam = raw.get("spam")

        if toxicity is None and spam is None:
            return None

    return {
        "categories": categories,
        "toxicity": _clamp(raw.get("toxicity"), 0.0, 1.0, 0.0),
        "spam": _clamp(raw.get("spam"), 0.0, 1.0, 0.0),
        "confidence": _clamp(raw.get("confidence"), 0.0, 1.0, 0.5),
        "suggested_action": action,
        "reason": str(raw.get("reason", ""))[:500],
        "language": _clean_language(raw.get("language")) or _clean_language(raw.get("lang")),
        "translation": str(raw.get("translation", ""))[:250],
    }