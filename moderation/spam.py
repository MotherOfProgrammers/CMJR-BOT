from database.database import get_connection
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from config import SPAM_MAX_MESSAGES, SPAM_SIMILARITY_THRESHOLD, SPAM_WINDOW_SECONDS


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def is_duplicate_message(
    sender: str,
    message: str,
    chat_id: str | None = None,
    window: int | None = None,
) -> bool:
    connection = get_connection()
    seconds = window if window is not None else SPAM_WINDOW_SECONDS
    threshold = SPAM_SIMILARITY_THRESHOLD
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=seconds)
    ).strftime("%Y-%m-%d %H:%M:%S")

    if chat_id:
        rows = connection.execute(
            """
            SELECT message
            FROM moderation_logs
            WHERE sender = ?
              AND chat_id = ?
              AND created_at >= ?
            ORDER BY id DESC
            LIMIT 25
            """,
            (sender, chat_id, cutoff),
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT message
            FROM moderation_logs
            WHERE sender = ?
              AND created_at >= ?
            ORDER BY id DESC
            LIMIT 25
            """,
            (sender, cutoff),
        ).fetchall()

    connection.close()

    for row in rows:
        if _similarity(row[0], message) >= threshold:
            return True

    return False


def is_repeated_link(sender: str, url: str, chat_id: str | None = None) -> bool:
    connection = get_connection()

    if chat_id:
        row = connection.execute(
            """
            SELECT id
            FROM moderation_logs
            WHERE sender = ?
              AND chat_id = ?
              AND message LIKE ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (sender, chat_id, f"%{url}%"),
        ).fetchone()
    else:
        row = connection.execute(
            """
            SELECT id
            FROM moderation_logs
            WHERE sender = ?
              AND message LIKE ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (sender, f"%{url}%"),
        ).fetchone()

    connection.close()

    return row is not None


def messages_in_last_seconds(
    sender: str,
    chat_id: str | None = None,
    seconds: int | None = None,
) -> int:
    connection = get_connection()
    window = seconds if seconds is not None else SPAM_WINDOW_SECONDS
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=window)
    ).strftime("%Y-%m-%d %H:%M:%S")

    if chat_id:
        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM moderation_logs
            WHERE sender = ?
              AND chat_id = ?
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
              AND created_at >= ?
            """,
            (sender, cutoff),
        ).fetchone()

    connection.close()

    return row[0]


def analyze_spam(
    sender: str,
    message: str,
    links: list[str],
    chat_id: str | None = None,
) -> dict:
    reasons = []
    risk = 0

    if is_duplicate_message(sender, message, chat_id=chat_id):
        risk += 2
        reasons.append("duplicate_message")

    for url in links:
        if is_repeated_link(sender, url, chat_id=chat_id):
            risk += 2
            reasons.append("repeated_link")
            break

    recent_messages = messages_in_last_seconds(
        sender,
        chat_id=chat_id,
        seconds=SPAM_WINDOW_SECONDS,
    )

    if recent_messages >= SPAM_MAX_MESSAGES:
        risk += 2
        reasons.append("message_flood")

    return {
        "risk": risk,
        "reasons": reasons,
    }