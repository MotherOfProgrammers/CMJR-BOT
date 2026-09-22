"""
!cmjr command engine.

Every command passes through the permission engine. A sender may issue a
command but still be denied based on their number/role/granular permission.
Unauthorized senders receive a short generic reply and no internal details.
"""

from auth.permissions import (
    can_run_command,
    permission_for_command,
)
from auth.identity import normalize_identity
from database.database import (
    get_chat_config,
    get_warning_count,
    get_moderation_stats,
    get_trusted_domains,
    increment_warning_count,
    reset_warning_count,
    save_chat_config,
    set_user_override,
    set_user_role,
    set_user_trusted,
)
from policy.models import (
    BLOCK,
    ChatConfig,
    SENSITIVITY_PRESETS,
)

PERMISSION_DENIED = "Permission denied."

COMMAND_NAMES = {
    "status",
    "help",
    "rules",
    "ai",
    "allow-links",
    "block-links",
    "warn",
    "delete",
    "block",
    "trust",
    "untrust",
    "permissions",
    "logs",
    "config",
    "banned",
}

HELP_TEXT = (
    "CMJR-BOT commands:\n"
    "!cmjr status\n"
    "!cmjr help\n"
    "!cmjr rules\n"
    "!cmjr ai\n"
    "!cmjr allow-links\n"
    "!cmjr block-links\n"
    "!cmjr warn @user\n"
    "!cmjr delete\n"
    "!cmjr block @user\n"
    "!cmjr trust @user\n"
    "!cmjr untrust @user\n"
    "!cmjr permissions\n"
    "!cmjr logs\n"
    "!cmjr config"
)


def parse_command_line(text: str) -> tuple[str | None, list[str]]:
    if not text:
        return None, []

    stripped = text.strip()
    lowered = stripped.lower()

    if not lowered.startswith("!cmjr"):
        return None, []

    parts = stripped.split()
    command = parts[1].lower() if len(parts) > 1 else ""

    if not command or command not in COMMAND_NAMES:
        return "help", parts[1:] if len(parts) > 1 else []

    return command, parts[2:]


def _extract_target(args: list[str]) -> str:
    for arg in args:
        if arg.startswith("@"):
            return normalize_identity(arg)["raw_jid"]

    return ""


def _deny():
    return {
        "handled": True,
        "reply": PERMISSION_DENIED,
        "action_request": None,
    }


def _chat(title: str, lines) -> str:
    body = "\n".join(line for line in lines if line)
    return f"{title}: {body}"


def _status(sender, chat_id, args):
    config = get_chat_config(chat_id)

    stats = get_moderation_stats()

    return _chat(
        "Status",
        [
            f"Bot: online",
            f"Provider: deterministic rules active",
            f"AI: "
            f"{'enabled' if config.effective_ai_enabled else 'disabled'}",
            f"Link policy: {config.effective_link_policy}",
            f"Block: {'on' if config.effective_auto_block else 'off'}",
            f"Delete: {'on' if config.effective_auto_delete else 'off'}",
            f"Warn: {'on' if config.effective_auto_warn else 'off'}",
            f"Messages monitored: {stats['total_messages']}",
            f"Incidents: {stats['total_incidents']}",
        ],
    )


def _help(sender, chat_id, args):
    return HELP_TEXT


def _rules(sender, chat_id, args):
    config = get_chat_config(chat_id)

    return _chat(
        "Active rules",
        [
            f"Sensitivity: {config.sensitivity}",
            f"Link policy: {config.effective_link_policy}",
            f"Toxicity scan: "
            f"{'on' if config.effective_toxicity_enabled else 'off'}",
            f"Spam scan: "
            f"{'on' if config.effective_spam_enabled else 'off'}",
            f"Auto warn: "
            f"{'on' if config.effective_auto_warn else 'off'}",
            f"Auto delete: "
            f"{'on' if config.effective_auto_delete else 'off'}",
            f"Auto block: "
            f"{'on' if config.effective_auto_block else 'off'}",
            f"Auto kick: "
            f"{'on' if config.effective_auto_kick else 'off'}",
        ],
    )


def _ai(sender, chat_id, args):
    permission = permission_for_command("ai")

    if not can_run_command(sender, "ai"):
        return _deny()

    current = get_chat_config(chat_id)

    if args:
        value = args[0].lower()

        if value in ("on", "enable", "1"):
            current.ai_enabled = True
            save_chat_config(current)
            return "AI analysis enabled for this chat."
        if value in ("off", "disable", "0"):
            current.ai_enabled = False
            save_chat_config(current)
            return "AI analysis disabled for this chat."

    state = "enabled" if current.effective_ai_enabled else "disabled"
    return (
        f"AI analysis: {state}. "
        f"Use '!cmjr ai on' or '!cmjr ai off' to change it."
    )


def _allow_links(sender, chat_id, args):
    if not can_run_command(sender, "allow-links"):
        return _deny()

    current = get_chat_config(chat_id)
    current.link_policy = "ALLOW_ALL"
    save_chat_config(current)

    return "Link policy set to ALLOW_ALL."


def _block_links(sender, chat_id, args):
    if not can_run_command(sender, "block-links"):
        return _deny()

    current = get_chat_config(chat_id)
    current.link_policy = "BLOCK_SUSPICIOUS"
    save_chat_config(current)

    return "Link policy set to BLOCK_SUSPICIOUS."


def _warn(sender, chat_id, args):
    if not can_run_command(sender, "warn"):
        return _deny()

    if args and args[0] == "del":
        reset_warning_count(chat_id, args[1] if len(args) > 1 else sender)
        return "Warning count reset."

    return "Warning recorded. Use '!cmjr warn @user' to warn a member."


def _delete(sender, chat_id, args, quoted_message_id=None):
    if not can_run_command(sender, "delete"):
        return _deny()

    target = _extract_target(args) or quoted_message_id or None

    return {
        "handled": True,
        "reply": "Message deleted.",
        "action_request": {
            "action": "DELETE",
            "chat_id": chat_id,
            "target_message_id": target,
        },
    }


def _block(sender, chat_id, args):
    if not can_run_command(sender, "block"):
        return _deny()

    target = _extract_target(args)

    if not target:
        return "Usage: !cmjr block @user"

    set_user_override(target, BLOCK)

    return f"{target} blocked."


def _trust(sender, chat_id, args):
    if not can_run_command(sender, "trust"):
        return _deny()

    target = _extract_target(args)

    if not target:
        return "Usage: !cmjr trust @user"

    set_user_trusted(target, True)

    return f"{target} marked as trusted."


def _untrust(sender, chat_id, args):
    if not can_run_command(sender, "untrust"):
        return _deny()

    target = _extract_target(args)

    if not target:
        return "Usage: !cmjr untrust @user"

    set_user_trusted(target, False)

    return f"{target} untrusted."


def _permissions(sender, chat_id, args):
    if not can_run_command(sender, "permissions"):
        return _deny()

    from auth.permissions import effective_permissions

    permissions = sorted(effective_permissions(sender))

    if not permissions:
        return "Your permissions: none (read-only)."

    return _chat(
        "Your permissions",
        permissions,
    )


def _logs(sender, chat_id, args):
    if not can_run_command(sender, "logs"):
        return _deny()

    from database.database import get_connection

    connection = get_connection()
    rows = connection.execute(
        """
        SELECT created_at, sender, risk, action
        FROM moderation_logs
        WHERE chat_id = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (chat_id,),
    ).fetchall()
    connection.close()

    if not rows:
        return "No recent events for this chat."

    return _chat(
        "Recent events",
        [
            f"{row[0]} | {row[1]} | risk {row[2]} | {row[3]}"
            for row in rows
        ],
    )


def _config(sender, chat_id, args):
    if not can_run_command(sender, "config"):
        return _deny()

    current = get_chat_config(chat_id)

    if not args:
        return _rules(sender, chat_id, args)

    return "Usage: !cmjr config (view only). Use the admin API to change settings."


HANDLERS = {
    "status": _status,
    "help": _help,
    "rules": _rules,
    "ai": _ai,
    "allow-links": _allow_links,
    "block-links": _block_links,
    "warn": _warn,
    "delete": _delete,
    "block": _block,
    "trust": _trust,
    "untrust": _untrust,
    "permissions": _permissions,
    "logs": _logs,
    "config": _config,
}


def handle_command(
    text: str,
    sender: str,
    chat_id: str,
    quoted_message_id: str | None = None,
) -> dict | None:
    command, args = parse_command_line(text)

    if command is None:
        return None

    handler = HANDLERS.get(command, _help)

    try:
        reply = handler(sender, chat_id, args, quoted_message_id)
    except TypeError:
        reply = handler(sender, chat_id, args)

    if isinstance(reply, dict):
        return reply

    return {
        "handled": True,
        "reply": reply,
        "action_request": None,
    }