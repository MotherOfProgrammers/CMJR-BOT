import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import config
from policy.models import ChatConfig


DATABASE_PATH = Path(__file__).parent / "cmjr.db"


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def _add_column_if_missing(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    ddl: str,
) -> None:
    rows = connection.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()
    existing = {row[1] for row in rows}

    if column not in existing:
        connection.execute(ddl)


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL UNIQUE,
            message_count INTEGER NOT NULL DEFAULT 0,
            warning_count INTEGER NOT NULL DEFAULT 0,
            high_risk_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _add_column_if_missing(
        connection,
        "users",
        "trusted",
        """
        ALTER TABLE users
        ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "override_action",
        """
        ALTER TABLE users
        ADD COLUMN override_action TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "role",
        """
        ALTER TABLE users
        ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "permissions",
        """
        ALTER TABLE users
        ADD COLUMN permissions TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "can_send_links",
        """
        ALTER TABLE users
        ADD COLUMN can_send_links INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "exempt_toxicity",
        """
        ALTER TABLE users
        ADD COLUMN exempt_toxicity INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "users",
        "exempt_spam",
        """
        ALTER TABLE users
        ADD COLUMN exempt_spam INTEGER
        """,
    )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS moderation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            risk INTEGER NOT NULL,
            action TEXT NOT NULL,
            warning TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _add_column_if_missing(
        connection,
        "moderation_logs",
        "chat_id",
        """
        ALTER TABLE moderation_logs
        ADD COLUMN chat_id TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "moderation_logs",
        "message_id",
        """
        ALTER TABLE moderation_logs
        ADD COLUMN message_id TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "moderation_logs",
        "message_hash",
        """
        ALTER TABLE moderation_logs
        ADD COLUMN message_hash TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "moderation_logs",
        "categories",
        """
        ALTER TABLE moderation_logs
        ADD COLUMN categories TEXT
        """,
    )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            risk INTEGER NOT NULL,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS chat_configs (
            chat_id TEXT PRIMARY KEY,
            sensitivity TEXT NOT NULL DEFAULT 'standard',
            high_risk_min_risk INTEGER,
            review_min_risk INTEGER,
            escalate_min_violations INTEGER,
            block_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _add_column_if_missing(
        connection,
        "chat_configs",
        "enabled",
        """
        ALTER TABLE chat_configs
        ADD COLUMN enabled INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "ai_enabled",
        """
        ALTER TABLE chat_configs
        ADD COLUMN ai_enabled INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "link_policy",
        """
        ALTER TABLE chat_configs
        ADD COLUMN link_policy TEXT
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "toxicity_enabled",
        """
        ALTER TABLE chat_configs
        ADD COLUMN toxicity_enabled INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "spam_enabled",
        """
        ALTER TABLE chat_configs
        ADD COLUMN spam_enabled INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "auto_delete",
        """
        ALTER TABLE chat_configs
        ADD COLUMN auto_delete INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "auto_warn",
        """
        ALTER TABLE chat_configs
        ADD COLUMN auto_warn INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "auto_block",
        """
        ALTER TABLE chat_configs
        ADD COLUMN auto_block INTEGER
        """,
    )

    _add_column_if_missing(
        connection,
        "chat_configs",
        "auto_kick",
        """
        ALTER TABLE chat_configs
        ADD COLUMN auto_kick INTEGER
        """,
    )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            sender TEXT,
            chat_id TEXT,
            risk INTEGER,
            action TEXT,
            rule TEXT,
            warning_count INTEGER,
            trusted INTEGER,
            override_action TEXT,
            detail TEXT,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_event_time
        ON audit_logs(event_time)
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS processed_messages (
            chat_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (chat_id, message_id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS trusted_domains (
            domain TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS warnings (
            chat_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (chat_id, sender)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS approved_members (
            sender TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("DROP TABLE IF EXISTS auto_delete_allowlist")

    connection.commit()
    connection.close()


def save_user_event(
    sender: str,
    action: str,
):
    connection = get_connection()

    warning = 0 if action == "ALLOW" else 1
    high_risk = 1 if action == "HIGH_RISK" else 0

    connection.execute(
        """
        INSERT INTO users (
            sender,
            message_count,
            warning_count,
            high_risk_count
        )
        VALUES (?, 1, ?, ?)
        ON CONFLICT(sender) DO UPDATE SET
            message_count = message_count + 1,
            warning_count = warning_count + ?,
            high_risk_count = high_risk_count + ?,
            last_seen = CURRENT_TIMESTAMP
        """,
        (
            sender,
            warning,
            high_risk,
            warning,
            high_risk,
        ),
    )

    connection.commit()
    connection.close()

def save_moderation_log(
    sender: str,
    message: str,
    risk: int,
    action: str,
    warning: str,
    chat_id: str | None = None,
    message_id: str | None = None,
    message_hash: str | None = None,
    categories: list | None = None,
):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO moderation_logs
        (sender, message, risk, action, warning, chat_id, message_id,
         message_hash, categories)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender,
            message,
            risk,
            action,
            warning,
            chat_id,
            message_id,
            message_hash,
            json.dumps(categories) if categories else None,
        ),
    )

    connection.commit()
    connection.close()

def save_incident(
    sender: str,
    risk: int,
    action: str,
    reason: str,
):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO incidents
        (sender, risk, action, reason)
        VALUES (?, ?, ?, ?)
        """,
        (sender, risk, action, reason),
    )

    connection.commit()
    connection.close()

def get_user(sender: str):
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

    connection.close()

    return user


def set_user_trusted(
    sender: str,
    trusted: bool,
) -> None:
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO users (
            sender,
            message_count,
            trusted
        )
        VALUES (?, 0, ?)
        ON CONFLICT(sender) DO UPDATE SET
            trusted = excluded.trusted,
            last_seen = CURRENT_TIMESTAMP
        """,
        (sender, int(trusted)),
    )

    connection.commit()
    connection.close()


def set_user_override(
    sender: str,
    action: str | None,
) -> None:
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO users (
            sender,
            message_count,
            override_action
        )
        VALUES (?, 0, ?)
        ON CONFLICT(sender) DO UPDATE SET
            override_action = excluded.override_action,
            last_seen = CURRENT_TIMESTAMP
        """,
        (sender, action),
    )

    connection.commit()
    connection.close()


def get_chat_config(chat_id: str) -> ChatConfig:
    connection = get_connection()

    row = connection.execute(
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
        WHERE chat_id = ?
        """,
        (chat_id,),
    ).fetchone()

    connection.close()

    if row is None:
        return ChatConfig(chat_id=chat_id)

    return ChatConfig(
        chat_id=row[0],
        sensitivity=row[1],
        high_risk_min_risk=row[2],
        review_min_risk=row[3],
        escalate_min_violations=row[4],
        block_enabled=bool(row[5]),
        enabled=_as_optional_bool(row[6]),
        ai_enabled=_as_optional_bool(row[7]),
        link_policy=row[8],
        toxicity_enabled=_as_optional_bool(row[9]),
        spam_enabled=_as_optional_bool(row[10]),
        auto_delete=_as_optional_bool(row[11]),
        auto_warn=_as_optional_bool(row[12]),
        auto_block=_as_optional_bool(row[13]),
        auto_kick=_as_optional_bool(row[14]),
    )


def _as_optional_bool(value):
    if value is None:
        return None
    return bool(value)


def _as_int_or_none(value):
    if value is None:
        return None
    return int(value)


def save_chat_config(config: ChatConfig) -> None:
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO chat_configs (
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
            auto_kick,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(chat_id) DO UPDATE SET
            sensitivity = excluded.sensitivity,
            high_risk_min_risk = excluded.high_risk_min_risk,
            review_min_risk = excluded.review_min_risk,
            escalate_min_violations = excluded.escalate_min_violations,
            block_enabled = excluded.block_enabled,
            enabled = excluded.enabled,
            ai_enabled = excluded.ai_enabled,
            link_policy = excluded.link_policy,
            toxicity_enabled = excluded.toxicity_enabled,
            spam_enabled = excluded.spam_enabled,
            auto_delete = excluded.auto_delete,
            auto_warn = excluded.auto_warn,
            auto_block = excluded.auto_block,
            auto_kick = excluded.auto_kick,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            config.chat_id,
            config.sensitivity,
            config.high_risk_min_risk,
            config.review_min_risk,
            config.escalate_min_violations,
            int(config.block_enabled),
            _as_int_or_none(config.enabled),
            _as_int_or_none(config.ai_enabled),
            config.link_policy,
            _as_int_or_none(config.toxicity_enabled),
            _as_int_or_none(config.spam_enabled),
            _as_int_or_none(config.auto_delete),
            _as_int_or_none(config.auto_warn),
            _as_int_or_none(config.auto_block),
            _as_int_or_none(config.auto_kick),
        ),
    )

    connection.commit()
    connection.close()


def get_warning_level(warning_count: int) -> str:
    if warning_count >= 5:
        return "ESCALATED"

    if warning_count >= 3:
        return "REPEATED_WARNING"

    if warning_count >= 1:
        return "WARNING"

    return "NORMAL"


def get_moderation_stats(days: int | None = None) -> dict:
    connection = get_connection()

    where = ""
    parameters = []
    if days is not None:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).strftime("%Y-%m-%d %H:%M:%S")
        where = " WHERE created_at >= ?"
        parameters.append(cutoff)

    total_messages = connection.execute(
        f"SELECT COUNT(*) FROM moderation_logs{where}",
        parameters,
    ).fetchone()[0]

    if days is None:
        warning_where = " WHERE action != 'ALLOW'"
        warning_parameters = []
    else:
        warning_where = " WHERE created_at >= ? AND action != 'ALLOW'"
        warning_parameters = parameters.copy()

    total_warnings = connection.execute(
        f"SELECT COUNT(*) FROM moderation_logs{warning_where}",
        warning_parameters,
    ).fetchone()[0]

    total_incidents = connection.execute(
        f"SELECT COUNT(*) FROM incidents{where}",
        parameters,
    ).fetchone()[0]

    action_rows = connection.execute(
        f"""
        SELECT action, COUNT(*)
        FROM moderation_logs
        {where or ''} GROUP BY action ORDER BY COUNT(*) DESC
        """,
        parameters,
    ).fetchall()

    risk_rows = connection.execute(
        f"""
        SELECT risk, COUNT(*)
        FROM moderation_logs
        {where or ''} GROUP BY risk ORDER BY risk DESC
        """,
        parameters,
    ).fetchall()

    offender_rows = connection.execute(
        f"""
        SELECT sender, COUNT(*)
        FROM incidents
        {where or ''} GROUP BY sender ORDER BY COUNT(*) DESC LIMIT 10
        """,
        parameters,
    ).fetchall()

    user_total = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    trusted_total = connection.execute(
        "SELECT COUNT(*) FROM users WHERE trusted = 1"
    ).fetchone()[0]

    connection.close()

    return {
        "total_messages": total_messages,
        "total_warnings": total_warnings,
        "total_incidents": total_incidents,
        "users_total": user_total,
        "trusted_total": trusted_total,
        "action_distribution": {
            row[0]: row[1] for row in action_rows
        },
        "risk_distribution": {
            row[0]: row[1] for row in risk_rows
        },
        "top_offenders": {
            row[0]: row[1] for row in offender_rows
        },
    }


def record_audit_event(
    event_type: str,
    sender: str | None = None,
    chat_id: str | None = None,
    risk: int | None = None,
    action: str | None = None,
    rule: str | None = None,
    warning_count: int | None = None,
    trusted: bool | None = None,
    override_action: str | None = None,
    detail: str | None = None,
) -> None:
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO audit_logs (
            event_type,
            sender,
            chat_id,
            risk,
            action,
            rule,
            warning_count,
            trusted,
            override_action,
            detail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            sender,
            chat_id,
            risk,
            action,
            rule,
            warning_count,
            int(trusted) if trusted is not None else None,
            override_action,
            detail,
        ),
    )

    connection.commit()
    connection.close()


def get_audit_events(
    limit: int = 100,
    sender: str | None = None,
    chat_id: str | None = None,
    event_type: str | None = None,
    action: str | None = None,
    rule: str | None = None,
) -> list:
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    query = """
        SELECT
            id,
            event_type,
            sender,
            chat_id,
            risk,
            action,
            rule,
            warning_count,
            trusted,
            override_action,
            detail,
            event_time
        FROM audit_logs
        WHERE 1 = 1
    """
    conditions = []
    parameters = []

    filters = (
        ("sender", sender),
        ("chat_id", chat_id),
        ("event_type", event_type),
        ("action", action),
        ("rule", rule),
    )

    for column, value in filters:
        if value is not None:
            conditions.append(f"{column} = ?")
            parameters.append(value)

    if conditions:
        query += " AND " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(limit)

    connection = get_connection()
    rows = connection.execute(query, parameters).fetchall()
    connection.close()

    return [
        {
            "id": row[0],
            "event_type": row[1],
            "sender": row[2],
            "chat_id": row[3],
            "risk": row[4],
            "action": row[5],
            "rule": row[6],
            "warning_count": row[7],
            "trusted": row[8],
            "override_action": row[9],
            "detail": row[10],
            "event_time": row[11],
        }
        for row in rows
    ]


# ============================================================
# IDEMPOTENCY
# ============================================================

def is_processed(chat_id: str, message_id: str) -> bool:
    if not chat_id or not message_id:
        return False

    connection = get_connection()
    row = connection.execute(
        """
        SELECT 1 FROM processed_messages
        WHERE chat_id = ? AND message_id = ?
        """,
        (chat_id, message_id),
    ).fetchone()
    connection.close()

    return row is not None


def mark_processed(chat_id: str, message_id: str, sender: str) -> None:
    if not chat_id or not message_id:
        return

    connection = get_connection()
    connection.execute(
        """
        INSERT OR IGNORE INTO processed_messages
        (chat_id, message_id, sender)
        VALUES (?, ?, ?)
        """,
        (chat_id, message_id, sender),
    )
    connection.commit()
    connection.close()


# ============================================================
# ROLE / PERMISSIONS
# ============================================================

def get_user_role(sender: str) -> str | None:
    connection = get_connection()
    row = connection.execute(
        "SELECT role FROM users WHERE sender = ?",
        (sender,),
    ).fetchone()
    connection.close()

    if row is None:
        return None
    return row[0]


def set_user_role(sender: str, role: str) -> None:
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO users (sender, message_count, role)
        VALUES (?, 0, ?)
        ON CONFLICT(sender) DO UPDATE SET
            role = excluded.role,
            last_seen = CURRENT_TIMESTAMP
        """,
        (sender, role),
    )
    connection.commit()
    connection.close()


def get_user_permissions(sender: str) -> dict | None:
    connection = get_connection()
    row = connection.execute(
        "SELECT permissions FROM users WHERE sender = ?",
        (sender,),
    ).fetchone()
    connection.close()

    if row is None or not row[0]:
        return None

    try:
        parsed = json.loads(row[0])
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        return None


def set_user_permissions(sender: str, permissions: dict) -> None:
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO users (sender, message_count, permissions)
        VALUES (?, 0, ?)
        ON CONFLICT(sender) DO UPDATE SET
            permissions = excluded.permissions,
            last_seen = CURRENT_TIMESTAMP
        """,
        (sender, json.dumps(permissions)),
    )
    connection.commit()
    connection.close()


def get_user_flags(sender: str) -> dict:
    connection = get_connection()
    row = connection.execute(
        """
        SELECT can_send_links, exempt_toxicity, exempt_spam
        FROM users
        WHERE sender = ?
        """,
        (sender,),
    ).fetchone()
    connection.close()

    if row is None:
        return {
            "can_send_links": False,
            "exempt_toxicity": False,
            "exempt_spam": False,
        }

    return {
        "can_send_links": bool(row[0]),
        "exempt_toxicity": bool(row[1]),
        "exempt_spam": bool(row[2]),
    }


def set_user_flag(sender: str, column: str, value: bool) -> None:
    allowed = {"can_send_links", "exempt_toxicity", "exempt_spam"}

    if column not in allowed:
        raise ValueError(f"Invalid user flag column: {column}")

    connection = get_connection()
    connection.execute(
        f"""
        INSERT INTO users (sender, message_count, {column})
        VALUES (?, 0, ?)
        ON CONFLICT(sender) DO UPDATE SET
            {column} = excluded.{column},
            last_seen = CURRENT_TIMESTAMP
        """,
        (sender, int(value)),
    )
    connection.commit()
    connection.close()


# ============================================================
# PER-CHAT WARNINGS
# ============================================================

def get_warning_count(chat_id: str, sender: str) -> int:
    connection = get_connection()
    row = connection.execute(
        """
        SELECT count FROM warnings
        WHERE chat_id = ? AND sender = ?
        """,
        (chat_id, sender),
    ).fetchone()
    connection.close()

    if row is None:
        return 0
    return row[0]


def increment_warning_count(chat_id: str, sender: str) -> int:
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO warnings (chat_id, sender, count)
        VALUES (?, ?, 1)
        ON CONFLICT(chat_id, sender) DO UPDATE SET
            count = count + 1,
            updated_at = CURRENT_TIMESTAMP
        """,
        (chat_id, sender),
    )
    connection.commit()
    count = connection.execute(
        "SELECT count FROM warnings WHERE chat_id = ? AND sender = ?",
        (chat_id, sender),
    ).fetchone()[0]
    connection.close()

    return count


def reset_warning_count(chat_id: str, sender: str) -> None:
    connection = get_connection()
    connection.execute(
        "DELETE FROM warnings WHERE chat_id = ? AND sender = ?",
        (chat_id, sender),
    )
    connection.commit()
    connection.close()


# ============================================================
# TRUSTED DOMAINS
# ============================================================

def is_trusted_domain(domain: str) -> bool:
    if not domain:
        return False

    connection = get_connection()
    row = connection.execute(
        "SELECT 1 FROM trusted_domains WHERE domain = ?",
        (domain.lower(),),
    ).fetchone()
    connection.close()

    return row is not None


def add_trusted_domain(domain: str) -> None:
    connection = get_connection()
    connection.execute(
        "INSERT OR IGNORE INTO trusted_domains (domain) VALUES (?)",
        (domain.lower(),),
    )
    connection.commit()
    connection.close()


def remove_trusted_domain(domain: str) -> None:
    connection = get_connection()
    connection.execute(
        "DELETE FROM trusted_domains WHERE domain = ?",
        (domain.lower(),),
    )
    connection.commit()
    connection.close()


def get_trusted_domains() -> list[str]:
    connection = get_connection()
    rows = connection.execute(
        "SELECT domain FROM trusted_domains ORDER BY domain"
    ).fetchall()
    connection.close()

    return [row[0] for row in rows]


# ============================================================
# APPROVED MEMBERS
#
# Members explicitly approved to send links. Only approved members
# may post links; every other sender's link message is deleted.
# Harmful content/words are always deleted, even from approved members.
# ============================================================

def is_approved_member(sender: str) -> bool:
    """True only when this sender number was explicitly approved in the DB."""
    if not sender:
        return False

    connection = get_connection()
    row = connection.execute(
        "SELECT 1 FROM approved_members WHERE sender = ?",
        (sender,),
    ).fetchone()
    connection.close()

    return row is not None


def add_approved_member(sender: str) -> None:
    connection = get_connection()
    connection.execute(
        "INSERT OR IGNORE INTO approved_members (sender) VALUES (?)",
        (sender,),
    )
    connection.commit()
    connection.close()


def remove_approved_member(sender: str) -> None:
    connection = get_connection()
    connection.execute(
        "DELETE FROM approved_members WHERE sender = ?",
        (sender,),
    )
    connection.commit()
    connection.close()


def get_approved_members() -> list[str]:
    connection = get_connection()
    rows = connection.execute(
        "SELECT sender FROM approved_members ORDER BY sender"
    ).fetchall()
    connection.close()

    return [row[0] for row in rows]
