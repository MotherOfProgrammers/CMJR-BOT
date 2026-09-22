"""
Granular, role + number based action permissions.

A user may hold permission for one action but not another. DB-level
permissions override the role defaults. Fail closed for administrative /
destructive actions.
"""

from database.database import get_user_permissions, get_user_role
from auth.identity import config_role_for, is_lid, role_rank


ALLOW_DELETE = "ALLOW_DELETE"
ALLOW_WARN = "ALLOW_WARN"
ALLOW_BLOCK = "ALLOW_BLOCK"
ALLOW_KICK = "ALLOW_KICK"
ALLOW_MUTE = "ALLOW_MUTE"
ALLOW_LINK_CONTROL = "ALLOW_LINK_CONTROL"
ALLOW_GROUP_SETTINGS = "ALLOW_GROUP_SETTINGS"
ALLOW_AI_OVERRIDE = "ALLOW_AI_OVERRIDE"
ALLOW_CONFIGURE_RULES = "ALLOW_CONFIGURE_RULES"

ALL_PERMISSIONS = (
    ALLOW_DELETE,
    ALLOW_WARN,
    ALLOW_BLOCK,
    ALLOW_KICK,
    ALLOW_MUTE,
    ALLOW_LINK_CONTROL,
    ALLOW_GROUP_SETTINGS,
    ALLOW_AI_OVERRIDE,
    ALLOW_CONFIGURE_RULES,
)

ROLE_PERMISSIONS = {
    "owner": set(ALL_PERMISSIONS),
    "admin": {
        ALLOW_DELETE,
        ALLOW_WARN,
        ALLOW_BLOCK,
        ALLOW_MUTE,
        ALLOW_LINK_CONTROL,
        ALLOW_GROUP_SETTINGS,
        ALLOW_AI_OVERRIDE,
        ALLOW_CONFIGURE_RULES,
    },
    "moderator": {
        ALLOW_DELETE,
        ALLOW_WARN,
    },
    "trusted": set(),
    "user": set(),
}

COMMAND_TO_PERMISSION = {
    "delete": ALLOW_DELETE,
    "warn": ALLOW_WARN,
    "block": ALLOW_BLOCK,
    "kick": ALLOW_KICK,
    "allow-links": ALLOW_LINK_CONTROL,
    "block-links": ALLOW_LINK_CONTROL,
    "trust": ALLOW_GROUP_SETTINGS,
    "untrust": ALLOW_GROUP_SETTINGS,
    "permissions": ALLOW_GROUP_SETTINGS,
    "config": ALLOW_CONFIGURE_RULES,
    "ai": ALLOW_AI_OVERRIDE,
}


class InvalidSenderId(Exception):
    pass


def resolve_role(sender: str | None) -> str:
    """Highest effective role for a sender. DB overrides env role when set."""
    if not sender:
        return "user"

    if is_lid(sender):
        return "user"

    db_role = get_user_role(sender)

    if db_role and db_role.lower() in ("owner", "admin", "moderator", "trusted"):
        return db_role.lower()

    env_role = config_role_for(sender)

    if env_role:
        return env_role

    return "user"


def effective_permissions(sender: str | None) -> set[str]:
    if not sender:
        return set()

    role = resolve_role(sender)
    permissions = set(ROLE_PERMISSIONS.get(role, set()))

    user_permissions = get_user_permissions(sender)

    if user_permissions:
        for name, enabled in user_permissions.items():
            if not isinstance(name, str):
                continue
            if not isinstance(enabled, bool):
                continue

            key = name.upper()

            if key not in ALL_PERMISSIONS:
                continue

            if enabled:
                permissions.add(key)
            else:
                permissions.discard(key)

    return permissions


def can(sender: str | None, permission: str) -> bool:
    return permission in effective_permissions(sender)


def banned_from_admin_actions(sender: str | None) -> bool:
    """LIDs are never allowed administrative authority."""
    if not sender:
        return True
    return is_lid(sender)


def permission_for_command(command: str) -> str | None:
    return COMMAND_TO_PERMISSION.get(command)


def can_run_command(sender: str | None, command: str) -> bool:
    permission = permission_for_command(command)

    if permission is None:
        return False

    if banned_from_admin_actions(sender):
        return False

    return can(sender, permission)


def maximum_role_name(sender: str | None) -> str:
    return resolve_role(sender)


def user_overrides_role(sender: str, role: str) -> bool:
    return role_rank(role) <= role_rank(resolve_role(sender))