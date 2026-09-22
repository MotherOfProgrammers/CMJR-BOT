import pytest
from fastapi.testclient import TestClient

from config import ADMIN_TOKEN
from database.database import (
    get_connection,
    initialize_database,
)
from main import app

client = TestClient(app, raise_server_exceptions=False)

AUTH = {"X-Admin-Token": ADMIN_TOKEN}


@pytest.fixture(autouse=True)
def clean_database():
    initialize_database()

    connection = get_connection()
    for table in (
        "audit_logs",
        "chat_configs",
        "moderation_logs",
        "incidents",
        "users",
        "processed_messages",
        "trusted_domains",
        "warnings",
        "approved_members",
    ):
        connection.execute(f"DELETE FROM {table}")
    connection.commit()
    connection.close()

    yield


def test_stats_requires_token():
    response = client.get("/admin/stats")
    assert response.status_code != 200

    response = client.get("/admin/stats", headers={"X-Admin-Token": "nope"})
    assert response.status_code == 401


def test_stats_empty_database():
    response = client.get("/admin/stats", headers=AUTH)
    assert response.status_code == 200
    stats = response.json()["stats"]
    assert stats["total_messages"] == 0
    assert stats["total_warnings"] == 0
    assert stats["total_incidents"] == 0
    assert stats["users_total"] == 0
    assert stats["trusted_total"] == 0
    assert stats["action_distribution"] == {}
    assert stats["risk_distribution"] == {}
    assert stats["top_offenders"] == {}


def test_stats_after_messages():
    from actions.replies import handle_message

    handle_message(sender="s-1", text="Hello everyone", chat_id="c1")
    handle_message(
        sender="s-1",
        text="Go to http://192.168.1.1/pay now",
        chat_id="c1",
    )
    handle_message(
        sender="s-2",
        text="Pay now to http://192.168.1.1/login and send otp",
        chat_id="c2",
    )

    stats = client.get("/admin/stats", headers=AUTH).json()["stats"]
    assert stats["total_messages"] == 3
    assert stats["users_total"] == 2
    assert stats["total_incidents"] >= 2


def test_stats_action_distribution():
    from actions.replies import handle_message

    handle_message(sender="d-1", text="Hello", chat_id="c1")
    handle_message(
        sender="d-2",
        text="Go to http://192.168.1.1/pay now",
        chat_id="c2",
    )
    handle_message(
        sender="d-3",
        text="Pay now to http://192.168.1.1/login and send otp",
        chat_id="c3",
    )

    stats = client.get("/admin/stats", headers=AUTH).json()["stats"]
    distribution = stats["action_distribution"]
    assert distribution.get("ALLOW") == 1
    assert distribution.get("DELETE") == 2


def test_stats_days_filter_rejects_invalid():
    response = client.get("/admin/stats", headers=AUTH, params={"days": 0})
    assert response.status_code == 422


def test_stats_days_filter_returns_window():
    response = client.get("/admin/stats", headers=AUTH, params={"days": 1})
    assert response.status_code == 200
    assert response.json()["days"] == 1
    assert response.json()["stats"]["total_messages"] == 0


def test_stats_top_offenders_ordering():
    from actions.replies import handle_message

    for _ in range(3):
        handle_message(
            sender="offender-1",
            text="Pay now http://bit.ly/1",
            chat_id="c1",
        )
    handle_message(
        sender="offender-2",
        text="Pay now http://bit.ly/2",
        chat_id="c1",
    )
    handle_message(
        sender="offender-3",
        text="Pay now http://bit.ly/3",
        chat_id="c1",
    )

    top = client.get("/admin/stats", headers=AUTH).json()["stats"]
    offenders = top["top_offenders"]
    assert offenders["offender-1"] >= 3


def test_health_endpoint_public():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_root_health_unchanged():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "online"}


def test_user_profile_includes_incidents():
    from actions.replies import handle_message

    handle_message(
        sender="profiled-1",
        text="Go to http://192.168.1.1/pay now",
        chat_id="c1",
    )

    user = client.get("/admin/users/profiled-1", headers=AUTH)
    assert user.status_code == 200
    assert "incidents" in user.json()
    assert len(user.json()["incidents"]) >= 1
    assert "action" in user.json()["incidents"][0]