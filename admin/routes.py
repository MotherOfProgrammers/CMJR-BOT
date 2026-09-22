from typing import Optional

import json

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from ai.providers import test_connection as ai_test_connection
from config import ADMIN_TOKEN, VALID_LINK_POLICIES
from database.database import (
    add_approved_member,
    get_approved_members,
    get_audit_events,
    get_chat_config,
    get_connection,
    get_moderation_stats,
    get_user_flags,
    get_user_permissions,
    get_user_role,
    get_warning_count,
    record_audit_event,
    remove_approved_member,
    save_chat_config,
    set_user_flag,
    set_user_override,
    set_user_permissions,
    set_user_role,
    set_user_trusted,
)
from policy.models import (
    ALL_ACTIONS,
    SENSITIVITY_PRESETS,
    ChatConfig,
)

router = APIRouter()

def verify_admin_token(x_admin_token: str):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin token",
        )


class ChatConfigUpdate(BaseModel):
    sensitivity: Optional[str] = None
    high_risk_min_risk: Optional[int] = Field(default=None, ge=0)
    review_min_risk: Optional[int] = Field(default=None, ge=0)
    escalate_min_violations: Optional[int] = Field(default=None, ge=1)
    block_enabled: Optional[bool] = None
    enabled: Optional[bool] = None
    ai_enabled: Optional[bool] = None
    link_policy: Optional[str] = None
    toxicity_enabled: Optional[bool] = None
    spam_enabled: Optional[bool] = None
    auto_delete: Optional[bool] = None
    auto_warn: Optional[bool] = None
    auto_block: Optional[bool] = None
    auto_kick: Optional[bool] = None
    reset: bool = False


class TrustedUpdate(BaseModel):
    trusted: bool


class OverrideUpdate(BaseModel):
    action: Optional[str] = None


class UserPermissionsUpdate(BaseModel):
    role: Optional[str] = None
    permissions: Optional[dict] = None
    flags: Optional[dict] = None


class ApprovedUpdate(BaseModel):
    approved: bool


def serialize_chat_config(config: ChatConfig) -> dict:
    return {
        "chat_id": config.chat_id,
        "sensitivity": config.sensitivity,
        "high_risk_min_risk": config.high_risk_min_risk,
        "review_min_risk": config.review_min_risk,
        "escalate_min_violations": config.escalate_min_violations,
        "block_enabled": config.block_enabled,
        "enabled": config.enabled,
        "ai_enabled": config.ai_enabled,
        "link_policy": config.link_policy,
        "toxicity_enabled": config.toxicity_enabled,
        "spam_enabled": config.spam_enabled,
        "auto_delete": config.auto_delete,
        "auto_warn": config.auto_warn,
        "auto_block": config.auto_block,
        "auto_kick": config.auto_kick,
        "effective_high_risk_min": config.effective_high_risk_min,
        "effective_review_min": config.effective_review_min,
        "effective_escalate_violations": config.effective_escalate_violations,
        "effective_enabled": config.effective_enabled,
        "effective_ai_enabled": config.effective_ai_enabled,
        "effective_link_policy": config.effective_link_policy,
        "effective_toxicity_enabled": config.effective_toxicity_enabled,
        "effective_spam_enabled": config.effective_spam_enabled,
        "effective_auto_delete": config.effective_auto_delete,
        "effective_auto_warn": config.effective_auto_warn,
        "effective_auto_block": config.effective_auto_block,
        "effective_auto_kick": config.effective_auto_kick,
    }


def validate_chat_config_update(body: ChatConfigUpdate):
    if body.sensitivity is not None:
        if body.sensitivity not in SENSITIVITY_PRESETS:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid sensitivity '{body.sensitivity}'. "
                    f"Choices: {', '.join(sorted(SENSITIVITY_PRESETS))}"
                ),
            )

    if body.link_policy is not None:
        if body.link_policy.upper() not in VALID_LINK_POLICIES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid link_policy '{body.link_policy}'. "
                    f"Choices: {', '.join(VALID_LINK_POLICIES)}"
                ),
            )

    high = body.high_risk_min_risk
    review = body.review_min_risk
    if high is not None and review is not None and high <= review:
        raise HTTPException(
            status_code=422,
            detail=(
                "high_risk_min_risk must be greater than review_min_risk"
            ),
        )

@router.get("/users")
async def get_users(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            sender,
            message_count,
            warning_count,
            high_risk_count,
            created_at,
            last_seen,
            trusted,
            override_action
        FROM users
        ORDER BY last_seen DESC
        """
    ).fetchall()

    connection.close()

    return {
        "users": [
            {
                "sender": row[0],
                "message_count": row[1],
                "warning_count": row[2],
                "high_risk_count": row[3],
                "created_at": row[4],
                "last_seen": row[5],
                "trusted": row[6],
                "override_action": row[7],
            }
            for row in rows
        ]
    }


@router.get("/users/approved")
async def list_approved_members(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)

    return {
        "approved_members": get_approved_members(),
        "note": (
            "Only approved members may send links. Link messages from "
            "any other sender are deleted automatically."
        ),
    }

@router.get("/logs")
async def get_logs(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            sender,
            message,
            risk,
            action,
            warning,
            created_at
        FROM moderation_logs
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return {
        "logs": [
            {
                "id": row[0],
                "sender": row[1],
                "message": row[2],
                "risk": row[3],
                "action": row[4],
                "warning": row[5],
                "created_at": row[6],
            }
            for row in rows
        ]
    }

@router.get("/incidents")
async def get_incidents(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            sender,
            risk,
            action,
            reason,
            created_at
        FROM incidents
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return {
        "incidents": [
            {
                "id": row[0],
                "sender": row[1],
                "risk": row[2],
                "action": row[3],
                "reason": row[4],
                "created_at": row[5],
            }
            for row in rows
        ]
    }

@router.get("/users/{sender}")
async def get_user(sender:str,x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    connection = get_connection()

    user = connection.execute(
        """
        SELECT
            sender,
            message_count,
            warning_count,
            high_risk_count,
            created_at,
            last_seen,
            trusted,
            override_action
        FROM users
        WHERE sender = ?
        """,
        (sender,),
    ).fetchone()

    if user is None:
        connection.close()

        return {
            "error": "User not found",
        }

    logs = connection.execute(
        """
        SELECT
            id,
            message,
            risk,
            action,
            warning,
            created_at
        FROM moderation_logs
        WHERE sender = ?
        ORDER BY id DESC
        """,
        (sender,),
    ).fetchall()

    incidents = connection.execute(
        """
        SELECT
            id,
            risk,
            action,
            reason,
            created_at
        FROM incidents
        WHERE sender = ?
        ORDER BY id DESC
        """,
        (sender,),
    ).fetchall()

    connection.close()

    return {
        "user": {
            "sender": user[0],
            "message_count": user[1],
            "warning_count": user[2],
            "high_risk_count": user[3],
            "created_at": user[4],
            "last_seen": user[5],
            "trusted": user[6],
            "override_action": user[7],
        },
        "moderation_logs": [
            {
                "id": row[0],
                "message": row[1],
                "risk": row[2],
                "action": row[3],
                "warning": row[4],
                "created_at": row[5],
            }
            for row in logs
        ],
        "incidents": [
            {
                "id": row[0],
                "risk": row[1],
                "action": row[2],
                "reason": row[3],
                "created_at": row[4],
            }
            for row in incidents
        ],
    }


@router.get("/chats/configs")
async def get_chat_configs(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            chat_id,
            sensitivity,
            high_risk_min_risk,
            review_min_risk,
            escalate_min_violations,
            block_enabled,
            enabled,
            ai_enabled,
            link_policy,
            toxicity_enabled,
            spam_enabled,
            auto_delete,
            auto_warn,
            auto_block,
            auto_kick
        FROM chat_configs
        ORDER BY chat_id
        """
    ).fetchall()

    connection.close()

    return {
        "chats": [
            serialize_chat_config(
                ChatConfig(
                    chat_id=row[0],
                    sensitivity=row[1],
                    high_risk_min_risk=row[2],
                    review_min_risk=row[3],
                    escalate_min_violations=row[4],
                    block_enabled=bool(row[5]),
                    enabled=row[6],
                    ai_enabled=row[7],
                    link_policy=row[8],
                    toxicity_enabled=row[9],
                    spam_enabled=row[10],
                    auto_delete=row[11],
                    auto_warn=row[12],
                    auto_block=row[13],
                    auto_kick=row[14],
                )
            )
            for row in rows
        ]
    }


@router.get("/chats/{chat_id}/config")
async def get_single_chat_config(
    chat_id: str,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)
    config = get_chat_config(chat_id)
    return serialize_chat_config(config)


@router.put("/chats/{chat_id}/config")
async def update_chat_config(
    chat_id: str,
    body: ChatConfigUpdate,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)
    validate_chat_config_update(body)

    base = ChatConfig(chat_id=chat_id)
    if not body.reset:
        base = get_chat_config(chat_id)

    config = ChatConfig(
        chat_id=chat_id,
        sensitivity=body.sensitivity
        if body.sensitivity is not None
        else base.sensitivity,
        high_risk_min_risk=body.high_risk_min_risk
        if body.high_risk_min_risk is not None
        else base.high_risk_min_risk,
        review_min_risk=body.review_min_risk
        if body.review_min_risk is not None
        else base.review_min_risk,
        escalate_min_violations=body.escalate_min_violations
        if body.escalate_min_violations is not None
        else base.escalate_min_violations,
        block_enabled=body.block_enabled
        if body.block_enabled is not None
        else base.block_enabled,
        enabled=body.enabled if body.enabled is not None else base.enabled,
        ai_enabled=body.ai_enabled
        if body.ai_enabled is not None
        else base.ai_enabled,
        link_policy=body.link_policy
        if body.link_policy is not None
        else base.link_policy,
        toxicity_enabled=body.toxicity_enabled
        if body.toxicity_enabled is not None
        else base.toxicity_enabled,
        spam_enabled=body.spam_enabled
        if body.spam_enabled is not None
        else base.spam_enabled,
        auto_delete=body.auto_delete
        if body.auto_delete is not None
        else base.auto_delete,
        auto_warn=body.auto_warn
        if body.auto_warn is not None
        else base.auto_warn,
        auto_block=body.auto_block
        if body.auto_block is not None
        else base.auto_block,
        auto_kick=body.auto_kick
        if body.auto_kick is not None
        else base.auto_kick,
    )

    save_chat_config(config)

    record_audit_event(
        event_type="admin_chat_config",
        chat_id=chat_id,
        detail=json.dumps(
            body.model_dump(exclude_unset=True),
        ),
    )

    return serialize_chat_config(config)


@router.put("/users/{sender}/trusted")
async def update_user_trusted(
    sender: str,
    body: TrustedUpdate,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)
    set_user_trusted(sender, body.trusted)

    record_audit_event(
        event_type="admin_user_trusted",
        sender=sender,
        detail=json.dumps({"trusted": body.trusted}),
    )

    return {
        "sender": sender,
        "trusted": body.trusted,
    }


@router.put("/users/{sender}/approved")
async def update_user_approved(
    sender: str,
    body: ApprovedUpdate,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)

    if body.approved:
        add_approved_member(sender)
    else:
        remove_approved_member(sender)

    record_audit_event(
        event_type="admin_user_approved",
        sender=sender,
        detail=json.dumps({"approved": body.approved}),
    )

    return {
        "sender": sender,
        "approved": body.approved,
    }


@router.put("/users/{sender}/override")
async def update_user_override(
    sender: str,
    body: OverrideUpdate,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)

    if body.action is not None and body.action not in ALL_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid action '{body.action}'. "
                f"Choices: {', '.join(ALL_ACTIONS)}"
            ),
        )

    set_user_override(sender, body.action)

    record_audit_event(
        event_type="admin_user_override",
        sender=sender,
        detail=json.dumps({"action": body.action}),
    )

    return {
        "sender": sender,
        "override_action": body.action,
    }


@router.get("/audit")
async def get_audit(
    x_admin_token: str = Header(),
    limit: int = 100,
    sender: Optional[str] = None,
    chat_id: Optional[str] = None,
    event_type: Optional[str] = None,
    action: Optional[str] = None,
    rule: Optional[str] = None,
):
    verify_admin_token(x_admin_token)

    events = get_audit_events(
        limit=limit,
        sender=sender,
        chat_id=chat_id,
        event_type=event_type,
        action=action,
        rule=rule,
    )

    return {
        "audit": events,
        "count": len(events),
    }


@router.get("/stats")
async def get_stats(
    x_admin_token: str = Header(),
    days: Optional[int] = None,
):
    verify_admin_token(x_admin_token)

    if days is not None and days < 1:
        raise HTTPException(
            status_code=422,
            detail="days must be >= 1",
        )

    return {
        "stats": get_moderation_stats(days=days),
        "days": days,
    }


@router.get("/ai/status")
async def get_ai_status(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)
    return await ai_test_connection()


@router.get("/rules")
async def get_active_rules(x_admin_token: str = Header()):
    verify_admin_token(x_admin_token)

    from config import (
        AI_PROVIDER,
        AUTO_BLOCK,
        AUTO_DELETE,
        AUTO_KICK,
        AUTO_WARN,
        DEFAULT_LINK_POLICY,
        OWNER_NUMBERS,
        ADMIN_NUMBERS,
        MODERATOR_NUMBERS,
        TRUSTED_NUMBERS,
        SPAM_MAX_MESSAGES,
        SPAM_SIMILARITY_THRESHOLD,
        SPAM_WINDOW_SECONDS,
        WARNING_THRESHOLD,
    )

    return {
        "rules": {
            "provider": "deterministic",
            "ai_provider": AI_PROVIDER,
            "default_link_policy": DEFAULT_LINK_POLICY,
            "auto_delete": AUTO_DELETE,
            "auto_warn": AUTO_WARN,
            "auto_block": AUTO_BLOCK,
            "auto_kick": AUTO_KICK,
            "spam_window_seconds": SPAM_WINDOW_SECONDS,
            "spam_max_messages": SPAM_MAX_MESSAGES,
            "spam_similarity_threshold": SPAM_SIMILARITY_THRESHOLD,
            "warning_threshold": WARNING_THRESHOLD,
            "roles_configured": {
                "owner_count": len([n for n in OWNER_NUMBERS.split(",") if n]),
                "admin_count": len([n for n in ADMIN_NUMBERS.split(",") if n]),
                "moderator_count": len([n for n in MODERATOR_NUMBERS.split(",") if n]),
                "trusted_count": len([n for n in TRUSTED_NUMBERS.split(",") if n]),
            },
        }
    }


@router.get("/groups/{chat_id}/moderation")
async def get_group_moderation(
    chat_id: str,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)

    connection = get_connection()

    warnings = connection.execute(
        """
        SELECT sender, count, updated_at
        FROM warnings
        WHERE chat_id = ?
        ORDER BY count DESC
        """,
        (chat_id,),
    ).fetchall()

    logs = connection.execute(
        """
        SELECT id, sender, message, risk, action, categories, created_at
        FROM moderation_logs
        WHERE chat_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (chat_id,),
    ).fetchall()

    connection.close()

    return {
        "chat_id": chat_id,
        "config": serialize_chat_config(get_chat_config(chat_id)),
        "warnings": [
            {"sender": row[0], "count": row[1], "updated_at": row[2]}
            for row in warnings
        ],
        "recent_logs": [
            {
                "id": row[0],
                "sender": row[1],
                "message": row[2],
                "risk": row[3],
                "action": row[4],
                "categories": row[5],
                "created_at": row[6],
            }
            for row in logs
        ],
    }


@router.get("/users/{sender}/permissions")
async def get_user_permissions_endpoint(
    sender: str,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)

    from auth.permissions import ALL_PERMISSIONS, effective_permissions, resolve_role

    return {
        "sender": sender,
        "role": resolve_role(sender),
        "effective_permissions": sorted(effective_permissions(sender)),
        "all_permissions": list(ALL_PERMISSIONS),
        "db_role": get_user_role(sender),
        "db_permissions": get_user_permissions(sender),
        "flags": get_user_flags(sender),
    }


@router.put("/users/{sender}/permissions")
async def update_user_permissions(
    sender: str,
    body: UserPermissionsUpdate,
    x_admin_token: str = Header(),
):
    verify_admin_token(x_admin_token)

    VALID_ROLES = {"owner", "admin", "moderator", "trusted", "user"}

    from auth.permissions import ALL_PERMISSIONS

    if body.role is not None:
        role = body.role.lower()

        if role not in VALID_ROLES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid role '{body.role}'. Choices: {', '.join(sorted(VALID_ROLES))}",
            )

        set_user_role(sender, role)

    if body.permissions is not None:
        cleaned = {}

        for name, enabled in body.permissions.items():
            if name.upper() not in ALL_PERMISSIONS:
                continue
            if not isinstance(enabled, bool):
                raise HTTPException(
                    status_code=422,
                    detail=f"permissions value for '{name}' must be boolean",
                )
            cleaned[name.upper()] = enabled

        set_user_permissions(sender, cleaned)

    if body.flags is not None:
        safe_flags = {"can_send_links", "exempt_toxicity", "exempt_spam"}

        for name, enabled in body.flags.items():
            if name not in safe_flags:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid flag '{name}'. Choices: {', '.join(sorted(safe_flags))}",
                )
            if not isinstance(enabled, bool):
                raise HTTPException(
                    status_code=422,
                    detail=f"value for '{name}' must be boolean",
                )
            set_user_flag(sender, name, enabled)

    record_audit_event(
        event_type="admin_user_permissions",
        sender=sender,
        detail=json.dumps(body.model_dump(exclude_unset=True)),
    )

    from auth.permissions import effective_permissions, resolve_role

    return {
        "sender": sender,
        "role": resolve_role(sender),
        "effective_permissions": sorted(effective_permissions(sender)),
        "flags": get_user_flags(sender),
    }
