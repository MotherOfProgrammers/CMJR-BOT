import hashlib
import json
import time

import httpx

from ai.parsers import normalize
from config import AI_API_KEY, AI_MODEL, AI_PROVIDER, AI_TIMEOUT, AI_URL


SUPPORTED_LANGUAGES = (
    "English, Sinhala, Tamil, Hindi, Urdu, Bengali, Nepali, Arabic, Spanish, "
    "French, Portuguese, Filipino (Tagalog), Indonesian, Swahili, Vietnamese, "
    "Chinese, Japanese, Korean, Russian, Turkish, and ANY other language"
)

SYSTEM_PROMPT = (
    "You are an advisory message classifier for a WhatsApp moderation bot. "
    "You are NEVER allowed to make a final decision — you only advise. "
    "Groups are multilingual. Detect abuse in ANY language, including: "
    + SUPPORTED_LANGUAGES
    + ". "
    "Recognize profanity, slurs, harassment, threats, scams and adult/18+ "
    "content whether the message is in English or in another script "
    "(e.g. Sinhala බූරුවා, Tamil முட்டாள், Hindi गधा, Arabic غبي, "
    "Japanese エッチ, Chinese 色情). "
    "Always report the message language via 'language' (ISO 639-1/-2). "
    "When you flag content, add a short 'translation' of the offending phrase "
    "into English to help a human reviewer. "
    "Output JSON only, with keys: categories (array of: SAFE, TOXIC, HARASSMENT, "
    "THREAT, SCAM, PHISHING, SPAM, VOLATILE, CONCERN, ADULT), toxicity (0-1), "
    "spam (0-1), confidence (0-1), suggested_action (ALLOW, REVIEW, BLOCK, "
    "ESCALATE), language (ISO 639-1/-2 code of the message), translation "
    "(English gloss of the flagged phrase or sentence, optional), reason "
    "(short, in English). "
    'Example: {"categories": ["TOXIC"], "toxicity": 0.9, "spam": 0.0, '
    '"confidence": 0.9, "suggested_action": "REVIEW", '
    '"language": "si", "translation": "you are a stupid donkey", '
    '"reason": "Sinhala insult (buruwa = donkey)"}'
)

DEFAULT_OLLAMA_MODEL = "llama3"

_CACHE: dict[str, dict] = {}
_CACHE_TTL_SECONDS = 60
_CACHE_MAX_ENTRIES = 256

_CACHE_TIMESTAMP: dict[str, float] = {}


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cache_get(key: str) -> dict | None:
    stamp = _CACHE_TIMESTAMP.get(key)

    if stamp is None:
        return None

    if time.time() - stamp > _CACHE_TTL_SECONDS:
        _CACHE.pop(key, None)
        _CACHE_TIMESTAMP.pop(key, None)

        return None

    return _CACHE.get(key)


def _cache_put(key: str, value: dict) -> None:
    if len(_CACHE) >= _CACHE_MAX_ENTRIES:
        _CACHE.clear()
        _CACHE_TIMESTAMP.clear()

    _CACHE[key] = value
    _CACHE_TIMESTAMP[key] = time.time()


async def _call_ollama(text: str) -> dict | None:
    model = AI_MODEL or DEFAULT_OLLAMA_MODEL
    timeout = httpx.Timeout(AI_TIMEOUT / 1000.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{AI_URL}/api/generate",
            json={
                "model": model,
                "prompt": f"{SYSTEM_PROMPT}\n\nMessage: {text}",
                "stream": False,
                "format": "json",
            },
        )
        response.raise_for_status()

        data = response.json()
        body = data.get("response", "{}")

    return normalize(json.loads(body))


async def _call_local(text: str) -> dict | None:
    model = AI_MODEL or ""
    timeout = httpx.Timeout(AI_TIMEOUT / 1000.0)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0.2,
    }

    headers = {"Content-Type": "application/json"}

    if AI_API_KEY:
        headers["Authorization"] = f"Bearer {AI_API_KEY}"

    base_url = AI_URL.rstrip("/")

    if base_url.endswith("/chat/completions"):
        url = base_url
    else:
        url = base_url + "/v1/chat/completions"

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]

    return normalize(json.loads(content))


async def analyze_text(text: str) -> dict | None:
    """Analyze text with the configured AI provider.

    Returns a validated advisory dict or None on any failure so callers always
    fall back to deterministic rules."""
    if not text:
        return None

    if AI_PROVIDER not in ("local", "ollama"):
        return None

    key = _cache_key(text)
    cached = _cache_get(key)

    if cached is not None:
        return cached

    try:
        if AI_PROVIDER == "ollama":
            result = await _call_ollama(text)
        else:
            result = await _call_local(text)
    except (httpx.HTTPError, KeyError, ValueError, IndexError, json.JSONDecodeError):
        return None

    if result is not None:
        _cache_put(key, result)

    return result


async def test_connection() -> dict:
    started = time.monotonic()

    if AI_PROVIDER not in ("local", "ollama"):
        return {
            "provider": AI_PROVIDER,
            "available": False,
            "reachable": False,
            "detail": "No AI provider configured (CMJR_AI_PROVIDER=none).",
        }

    try:
        advisory = await analyze_text("ping")

        if advisory is None:
            return {
                "provider": AI_PROVIDER,
                "model": AI_MODEL or DEFAULT_OLLAMA_MODEL,
                "url": AI_URL,
                "reachable": False,
                "available": False,
                "detail": (
                    "AI provider did not return a usable response "
                    "(missing/invalid API key, denied access, or bad URL)."
                ),
            }

        return {
            "provider": AI_PROVIDER,
            "model": AI_MODEL or DEFAULT_OLLAMA_MODEL,
            "url": AI_URL,
            "reachable": True,
            "available": True,
            "detail": "Connected and returnable responses.",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as error:  # noqa: BLE001 - reported for the admin panel
        return {
            "provider": AI_PROVIDER,
            "model": AI_MODEL or DEFAULT_OLLAMA_MODEL,
            "url": AI_URL,
            "reachable": False,
            "available": False,
            "detail": f"{type(error).__name__}: {error}",
        }