import pytest

from database.database import get_connection, initialize_database
from config import ADMIN_TOKEN, WEBHOOK_TOKEN


TABLES = (
    "audit_logs",
    "chat_configs",
    "moderation_logs",
    "incidents",
    "users",
    "processed_messages",
    "trusted_domains",
    "warnings",
    "approved_members",
)


@pytest.fixture(autouse=True)
def clean_database():
    initialize_database()

    connection = get_connection()
    for table in TABLES:
        connection.execute(f"DELETE FROM {table}")
    connection.commit()
    connection.close()

    yield


@pytest.fixture()
def webhook_headers():
    return {"X-Webhook-Token": WEBHOOK_TOKEN}


@pytest.fixture()
def admin_headers():
    return {"X-Admin-Token": ADMIN_TOKEN}