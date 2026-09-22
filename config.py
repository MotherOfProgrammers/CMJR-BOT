import logging
import os

from dotenv import load_dotenv


load_dotenv()


logger = logging.getLogger("cmjr.config")

VALID_PROVIDERS = ("generic", "meta")

VALID_AI_PROVIDERS = ("none", "local", "ollama")

VALID_LINK_POLICIES = (
    "ALLOW_ALL",
    "REVIEW_UNKNOWN",
    "BLOCK_SUSPICIOUS",
    "BLOCK_ALL_EXTERNAL",
    "ALLOW_TRUSTED_ONLY",
)

DEFAULT_TOKEN_PLACEHOLDER = "change-this"


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        logger.warning(
            "Invalid integer for env variable, falling back to %s: %r",
            default,
            value,
        )
        return default


def _parse_float(value: str | None, default: float) -> float:
    if value is None:
        return default

    try:
        return float(value)
    except ValueError:
        logger.warning(
            "Invalid number for env variable, falling back to %s: %r",
            default,
            value,
        )
        return default


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in ("1", "true", "yes", "on"):
        return True

    if normalized in ("0", "false", "no", "off"):
        return False

    logger.warning(
        "Invalid boolean for env variable, falling back to %s: %r",
        default,
        value,
    )
    return default


WEBHOOK_TOKEN = os.getenv("CMJR_WEBHOOK_TOKEN")
ADMIN_TOKEN = os.getenv("CMJR_ADMIN_TOKEN")
MAX_PAYLOAD_BYTES = _parse_int(
    os.getenv("CMJR_MAX_PAYLOAD_BYTES"),
    100000,
)

PROVIDER = os.getenv("CMJR_PROVIDER", "generic")

META_APP_ID = os.getenv("CMJR_META_APP_ID")
META_APP_SECRET = os.getenv("CMJR_META_APP_SECRET")
META_VERIFY_TOKEN = os.getenv("CMJR_META_VERIFY_TOKEN")
META_ACCESS_TOKEN = os.getenv("CMJR_META_ACCESS_TOKEN")
META_PHONE_NUMBER_ID = os.getenv("CMJR_META_PHONE_NUMBER_ID")
META_API_VERSION = os.getenv("CMJR_META_API_VERSION", "v25.0")
META_GRAPH_URL = os.getenv(
    "CMJR_META_GRAPH_URL",
    "https://graph.facebook.com",
)

AI_PROVIDER = os.getenv("CMJR_AI_PROVIDER", "none").lower()
AI_MODEL = os.getenv("CMJR_AI_MODEL", "")
AI_TIMEOUT = _parse_int(os.getenv("CMJR_AI_TIMEOUT"), 5000)
AI_URL = os.getenv("CMJR_AI_URL", "http://127.0.0.1:11434")
AI_API_KEY = os.getenv("CMJR_AI_API_KEY", "")

AUTO_DELETE = _parse_bool(os.getenv("CMJR_AUTO_DELETE"), False)
AUTO_WARN = _parse_bool(os.getenv("CMJR_AUTO_WARN"), True)
AUTO_BLOCK = _parse_bool(os.getenv("CMJR_AUTO_BLOCK"), False)
AUTO_KICK = _parse_bool(os.getenv("CMJR_AUTO_KICK"), False)

SPAM_WINDOW_SECONDS = _parse_int(os.getenv("CMJR_SPAM_WINDOW_SECONDS"), 10)
SPAM_MAX_MESSAGES = _parse_int(os.getenv("CMJR_SPAM_MAX_MESSAGES"), 5)
SPAM_SIMILARITY_THRESHOLD = _parse_float(
    os.getenv("CMJR_SPAM_SIMILARITY_THRESHOLD"),
    0.90,
)

WARNING_THRESHOLD = _parse_int(os.getenv("CMJR_WARNING_THRESHOLD"), 3)

DEFAULT_LINK_POLICY = os.getenv(
    "CMJR_DEFAULT_LINK_POLICY",
    "REVIEW_UNKNOWN",
).upper()

OWNER_NUMBERS = os.getenv("CMJR_OWNER_NUMBERS", "")
ADMIN_NUMBERS = os.getenv("CMJR_ADMIN_NUMBERS", "")
MODERATOR_NUMBERS = os.getenv("CMJR_MODERATOR_NUMBERS", "")
TRUSTED_NUMBERS = os.getenv("CMJR_TRUSTED_NUMBERS", "")
TRUSTED_LINK_SENDERS = os.getenv("CMJR_TRUSTED_LINK_SENDERS", "")


def validate_config() -> None:
    if PROVIDER not in VALID_PROVIDERS:
        raise ValueError(
            f"CMJR_PROVIDER must be one of {', '.join(VALID_PROVIDERS)}, "
            f"got '{PROVIDER}'"
        )

    if MAX_PAYLOAD_BYTES < 1024:
        logger.warning(
            "CMJR_MAX_PAYLOAD_BYTES is very small (%s); "
            "watches may reject legitimate payloads",
            MAX_PAYLOAD_BYTES,
        )

    for name, value in (
        ("CMJR_WEBHOOK_TOKEN", WEBHOOK_TOKEN),
        ("CMJR_ADMIN_TOKEN", ADMIN_TOKEN),
    ):
        if not value:
            logger.warning("%s is not set; authentication is disabled", name)
        elif DEFAULT_TOKEN_PLACEHOLDER in value.lower():
            logger.warning(
                "%s still uses a placeholder value; rotation is required",
                name,
            )

    if PROVIDER == "meta":
        missing = [
            name
            for name, value in (
                ("CMJR_META_APP_SECRET", META_APP_SECRET),
                ("CMJR_META_ACCESS_TOKEN", META_ACCESS_TOKEN),
                ("CMJR_META_PHONE_NUMBER_ID", META_PHONE_NUMBER_ID),
                ("CMJR_META_VERIFY_TOKEN", META_VERIFY_TOKEN),
            )
            if not value
        ]
        if missing:
            logger.warning(
                "Provider is 'meta' but credentials are incomplete; "
                "missing: %s. Inbound messages will be accepted and "
                "outbound replies will fail.",
                ", ".join(missing),
            )

    if AI_PROVIDER not in VALID_AI_PROVIDERS:
        raise ValueError(
            f"CMJR_AI_PROVIDER must be one of "
            f"{', '.join(VALID_AI_PROVIDERS)}, got '{AI_PROVIDER}'"
        )

    if AI_PROVIDER == "ollama":
        logger.info(
            "AI provider is 'ollama'. Requests will target %s using "
            "model '%s'. If Ollama is unreachable, the bot falls back "
            "to deterministic rules.",
            AI_URL,
            AI_MODEL or "(default)",
        )

    if DEFAULT_LINK_POLICY not in VALID_LINK_POLICIES:
        raise ValueError(
            f"CMJR_DEFAULT_LINK_POLICY must be one of "
            f"{', '.join(VALID_LINK_POLICIES)}, got '{DEFAULT_LINK_POLICY}'"
        )

    if SPAM_WINDOW_SECONDS < 1:
        logger.warning(
            "CMJR_SPAM_WINDOW_SECONDS is %s; using 1 instead",
            SPAM_WINDOW_SECONDS,
        )

    if not (0.0 <= SPAM_SIMILARITY_THRESHOLD <= 1.0):
        raise ValueError(
            "CMJR_SPAM_SIMILARITY_THRESHOLD must be between 0.0 and 1.0, "
            f"got {SPAM_SIMILARITY_THRESHOLD}"
        )

    if WARNING_THRESHOLD < 1:
        logger.warning(
            "CMJR_WARNING_THRESHOLD is %s; using 1 instead",
            WARNING_THRESHOLD,
        )
