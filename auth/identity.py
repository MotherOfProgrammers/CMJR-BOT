"""
Identity and role resolution for WhatsApp numbers/JIDs.

Normalizes numbers/jids before any comparison. A LID (linked id) is treated
as an opaque identity and is never assumed to equal the phone number.
"""

import config


ROLE_ORDER = {
    "owner": 5,
    "admin": 4,
    "moderator": 3,
    "trusted": 2,
    "user": 1,
}

VALID_ROLES = tuple(ROLE_ORDER)


def normalize_identity(raw: str | None) -> dict:
    """Return raw_jid / normalized_identity / kind for a sender identity."""
    if not raw:
        return {
            "raw_jid": "",
            "normalized_identity": "",
            "kind": "unknown",
        }

    value = str(raw).strip()

    if not value:
        return {
            "raw_jid": value,
            "normalized_identity": "",
            "kind": "unknown",
        }

    domain = None
    user = value

    if "@" in value:
        user, _, domain = value.partition("@")
        domain = domain.lower()

    if domain and domain.startswith("lid"):
        return {
            "raw_jid": value,
            "normalized_identity": user,
            "kind": "lid",
        }

    digits = "".join(ch for ch in user if ch.isdigit())

    if not digits:
        return {
            "raw_jid": value,
            "normalized_identity": value,
            "kind": "unknown",
        }

    return {
        "raw_jid": value,
        "normalized_identity": digits,
        "kind": "phone",
    }


def is_lid(raw: str | None) -> bool:
    return ("@" in (raw or "")) and (raw or "").split("@", 1)[1].startswith("lid")


def normalized_phone(raw: str | None) -> str | None:
    identity = normalize_identity(raw)

    if identity["kind"] != "phone":
        return None

    return identity["normalized_identity"]


def parse_number_set(raw_value: str | None) -> set[str]:
    """Parse a comma/space separated number list into normalized phones."""
    if not raw_value:
        return set()

    phones = set()

    for part in raw_value.replace(";", ",").replace("\n", ",").split(","):
        number = normalized_phone(part.strip())

        if number:
            phones.add(number)

    return phones


def role_rank(role: str | None) -> int:
    if not role:
        return 0
    return ROLE_ORDER.get(role.lower(), 0)


def config_role_for(sender: str | None) -> str | None:
    """Determine the role implied by the environment number lists."""
    number = normalized_phone(sender)

    if number is None:
        return None

    if number in parse_number_set(config.OWNER_NUMBERS):
        return "owner"

    if number in parse_number_set(config.ADMIN_NUMBERS):
        return "admin"

    if number in parse_number_set(config.MODERATOR_NUMBERS):
        return "moderator"

    if number in parse_number_set(config.TRUSTED_NUMBERS):
        return "trusted"

    return None


def config_is_trusted(sender: str | None) -> bool:
    number = normalized_phone(sender)

    if number is None:
        return False

    return number in (
        parse_number_set(config.OWNER_NUMBERS)
        | parse_number_set(config.ADMIN_NUMBERS)
        | parse_number_set(config.MODERATOR_NUMBERS)
        | parse_number_set(config.TRUSTED_NUMBERS)
    )


def config_can_send_links(sender: str | None) -> bool:
    number = normalized_phone(sender)

    if number is None:
        return False

    return number in parse_number_set(config.TRUSTED_LINK_SENDERS)