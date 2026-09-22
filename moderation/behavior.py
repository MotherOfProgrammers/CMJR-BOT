from database.database import get_connection, get_warning_count
from datetime import datetime, timedelta, timezone

from config import WARNING_THRESHOLD


def _recent_high_risk_count(sender: str, chat_id: str | None, minutes: int = 60) -> int:
    connection = get_connection()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    if chat_id:
        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM moderation_logs
            WHERE sender = ?
              AND chat_id = ?
              AND action IN ('HIGH_RISK', 'REVIEW', 'BLOCK', 'ESCALATE')
              AND created_at >= ?
            """,
            (sender, chat_id, cutoff),
        ).fetchone()
    else:
        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM moderation_logs
            WHERE sender = ?
              AND action IN ('HIGH_RISK', 'REVIEW', 'BLOCK', 'ESCALATE')
              AND created_at >= ?
            """,
            (sender, cutoff),
        ).fetchone()

    connection.close()

    return row[0] if row else 0


def analyze_behavior(
    sender: str,
    chat_id: str | None = None,
    current_risk: int = 0,
    categories: list[str] | None = None,
) -> dict:
    risk = 0
    reasons = []
    categories = categories or []

    warning_count = get_warning_count(chat_id, sender) if chat_id else 0
    recent_incidents = _recent_high_risk_count(sender, chat_id)

    if recent_incidents >= 3:
        risk += 2
        reasons.append("repeat_offender")
        categories.append("BEHAVIOR")

    if warning_count >= WARNING_THRESHOLD:
        risk += 2
        reasons.append("warning_threshold_reached")
        categories.append("BEHAVIOR")

    if current_risk >= 6:
        risk += 1
        reasons.append("sustained_high_risk")
        categories.append("BEHAVIOR")

    return {
        "risk": risk,
        "reasons": reasons,
        "categories": categories,
        "warning_count": warning_count,
        "recent_incidents": recent_incidents,
    }