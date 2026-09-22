import hashlib

from actions.warning import warning_message
from ai.providers import analyze_text
from auth.permissions import resolve_role
from database.database import (
    get_chat_config,
    get_user,
    get_user_flags,
    increment_warning_count,
    is_processed,
    mark_processed,
    record_audit_event,
    save_incident,
    save_moderation_log,
    save_user_event,
)
from decision.engine import evaluate_message
from message_parser import parse_message
from moderation.behavior import analyze_behavior
from moderation.rules import analyze_message
from moderation.toxicity import detect_toxicity
from policy.models import ALLOW


def _message_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _process(
    sender: str,
    text: str,
    chat_id: str | None = None,
    message_id: str | None = None,
    message_type: str | None = None,
    chat_type: str | None = None,
    ai: dict | None = None,
) -> dict:
    message = parse_message(sender, text)
    chat_key = chat_id or "default"

    analysis = analyze_message(
        sender=message.sender,
        text=message.text,
        chat_id=chat_key,
    )

    chat_config = get_chat_config(chat_key)

    if not chat_config.effective_enabled:
        save_moderation_log(
            sender=message.sender,
            message=message.text,
            risk=analysis["risk"],
            action=ALLOW,
            warning="",
            chat_id=chat_key,
            message_id=message_id,
            message_hash=_message_hash(message.text),
            categories=None,
        )

        return {
            "sender": message.sender,
            "text": message.text,
            "chat_id": chat_key,
            "message_id": message_id,
            "message_type": message_type,
            "chat_type": chat_type,
            "risk": analysis["risk"],
            "action": ALLOW,
            "risk_label": "SAFE",
            "warning": "",
            "scam": analysis["scam"],
            "links": analysis["links"],
            "categories": [],
            "policy": {"rule": "chat_disabled", "chat_id": chat_key},
            "ai_used": False,
            "decision": None,
        }

    user = get_user(message.sender)
    legacy_trusted = bool(user[6]) if user else False
    override_action = user[7] if user else None

    flags = get_user_flags(message.sender)
    role = resolve_role(message.sender)
    trusted = legacy_trusted or role in ("owner", "admin", "moderator", "trusted")

    toxicity = None

    if chat_config.effective_toxicity_enabled and not flags["exempt_toxicity"]:
        toxicity = detect_toxicity(message.text)

    behavior = analyze_behavior(
        sender=message.sender,
        chat_id=chat_key,
        current_risk=analysis["risk"],
    )

    decision = evaluate_message(
        analysis=analysis,
        toxicity=toxicity,
        behavior=behavior,
        ai=ai,
        chat_config=chat_config,
        sender=message.sender,
        chat_id=chat_key,
        trusted=trusted,
        role=role,
        can_send_links=flags["can_send_links"],
        exempt_toxicity=flags["exempt_toxicity"],
        exempt_spam=flags["exempt_spam"],
        override_action=override_action,
    )

    action = decision["action"]

    if decision["should_warn"]:
        increment_warning_count(chat_key, message.sender)

    warning = warning_message(
        action,
        decision["reasons"],
    )

    record_audit_event(
        event_type="policy_decision",
        sender=message.sender,
        chat_id=chat_key,
        risk=decision["risk"],
        action=action,
        rule=decision["rule"],
        warning_count=behavior.get("warning_count", 0),
        trusted=trusted,
        detail=(
            "AI advisory"
            + (f" ({ai.get('language')})" if ai and ai.get("language") else "")
            + (f": {ai.get('translation')}" if ai and ai.get("translation") else "")
        )
        if ai is not None
        else None,
    )

    save_moderation_log(
        sender=message.sender,
        message=message.text,
        risk=decision["risk"],
        action=action,
        warning=warning,
        chat_id=chat_key,
        message_id=message_id,
        message_hash=_message_hash(message.text),
        categories=decision["categories"],
    )
    save_user_event(
        sender=message.sender,
        action=action,
    )
    if action != ALLOW:
        save_incident(
            sender=message.sender,
            risk=decision["risk"],
            action=action,
            reason=", ".join(decision["reasons"]),
        )

    return {
        "sender": message.sender,
        "text": message.text,
        "chat_id": chat_key,
        "message_id": message_id,
        "message_type": message_type,
        "chat_type": chat_type,
        "risk": decision["risk"],
        "risk_label": decision["risk_label"],
        "action": action,
        "warning": warning,
        "scam": analysis["scam"],
        "links": analysis["links"],
        "categories": decision["categories"],
        "ai_used": decision["ai_used"],
        "ai_advisory": decision["ai_advisory"],
        "policy": {
            "rule": decision["rule"],
            "chat_id": chat_key,
            "link_verdict": decision["link_verdict"],
        },
        "decision": decision,
    }


def handle_message(
    sender: str,
    text: str,
    chat_id: str | None = None,
) -> dict:
    return _process(
        sender=sender,
        text=text,
        chat_id=chat_id,
    )


async def handle_message_full(
    sender: str,
    text: str,
    chat_id: str | None = None,
    message_id: str | None = None,
    message_type: str | None = None,
    chat_type: str | None = None,
) -> dict:
    if chat_id and message_id and is_processed(chat_id, message_id):
        return {
            "status": "duplicate_skipped",
            "sender": sender,
            "text": text,
            "chat_id": chat_id,
            "message_id": message_id,
            "action": "SKIPPED",
            "warning": "",
        }

    chat_key = chat_id or "default"
    chat_config = get_chat_config(chat_key)
    ai = None

    if chat_config.effective_ai_enabled:
        ai = await analyze_text(text)

    result = _process(
        sender=sender,
        text=text,
        chat_id=chat_id,
        message_id=message_id,
        message_type=message_type,
        chat_type=chat_type,
        ai=ai,
    )

    if chat_id and message_id:
        mark_processed(chat_id, message_id, sender)

    return result