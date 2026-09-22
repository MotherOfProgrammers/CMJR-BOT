import pytest
from fastapi.testclient import TestClient

from config import ADMIN_TOKEN
from database.database import (
    get_connection,
    initialize_database,
)
from main import app

client = TestClient(app, raise_server_exceptions=False)

TOKEN = ADMIN_TOKEN

AUTH = {"X-Admin-Token": TOKEN}


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


def test_admin_endpoints_require_token():
    assert client.get("/admin/chats/configs").status_code != 200
    assert (
        client.get(
            "/admin/chats/configs",
            headers={"X-Admin-Token": "wrong-token"},
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/admin/chats/configs",
            headers={"X-Admin-Token": "wrong-token"},
        ).json()["detail"]
        == "Invalid admin token"
    )


def test_admin_endpoints_require_token_for_puts():
    assert (
        client.put(
            "/admin/chats/chat-1/config",
            json={"sensitivity": "strict"},
        ).status_code
        != 200
    )
    assert (
        client.put(
            "/admin/users/sender-1/trusted",
            json={"trusted": True},
        ).status_code
        != 200
    )
    assert (
        client.put(
            "/admin/users/sender-1/override",
            json={"action": "BLOCK"},
        ).status_code
        != 200
    )


def test_list_chat_configs_empty_by_default():
    response = client.get("/admin/chats/configs", headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {"chats": []}


def test_get_chat_config_returns_defaults():
    response = client.get("/admin/chats/chat-1/config", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["chat_id"] == "chat-1"
    assert body["sensitivity"] == "standard"
    assert body["block_enabled"] is False
    assert body["effective_high_risk_min"] == 4
    assert body["effective_review_min"] == 2
    assert body["effective_escalate_violations"] == 5


def test_update_chat_config_persists():
    response = client.put(
        "/admin/chats/chat-1/config",
        headers=AUTH,
        json={
            "sensitivity": "strict",
            "block_enabled": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sensitivity"] == "strict"
    assert body["block_enabled"] is True
    assert body["effective_high_risk_min"] == 3

    fetched = client.get("/admin/chats/chat-1/config", headers=AUTH)
    assert fetched.json()["sensitivity"] == "strict"
    assert fetched.json()["block_enabled"] is True

    listed = client.get("/admin/chats/configs", headers=AUTH)
    assert len(listed.json()["chats"]) == 1
    assert listed.json()["chats"][0]["chat_id"] == "chat-1"


def test_update_chat_config_threshold_overrides():
    response = client.put(
        "/admin/chats/chat-2/config",
        headers=AUTH,
        json={
            "high_risk_min_risk": 6,
            "review_min_risk": 3,
            "escalate_min_violations": 2,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["high_risk_min_risk"] == 6
    assert body["review_min_risk"] == 3
    assert body["escalate_min_violations"] == 2
    assert body["effective_high_risk_min"] == 6


def test_reject_invalid_sensitivity():
    response = client.put(
        "/admin/chats/chat-3/config",
        headers=AUTH,
        json={"sensitivity": "extreme"},
    )
    assert response.status_code == 422
    assert "sensitivity" in response.json()["detail"]


def test_reject_high_risk_not_above_review():
    response = client.put(
        "/admin/chats/chat-3/config",
        headers=AUTH,
        json={
            "high_risk_min_risk": 2,
            "review_min_risk": 2,
        },
    )
    assert response.status_code == 422


def test_reject_negative_threshold():
    response = client.put(
        "/admin/chats/chat-3/config",
        headers=AUTH,
        json={"review_min_risk": -1},
    )
    assert response.status_code == 422


def test_update_preserves_unspecified_fields():
    client.put(
        "/admin/chats/chat-4/config",
        headers=AUTH,
        json={
            "sensitivity": "lenient",
            "block_enabled": True,
        },
    )

    response = client.put(
        "/admin/chats/chat-4/config",
        headers=AUTH,
        json={"sensitivity": "strict"},
    )
    body = response.json()
    assert body["sensitivity"] == "strict"
    assert body["block_enabled"] is True


def test_update_with_reset_reverts_unset_fields():
    client.put(
        "/admin/chats/chat-5/config",
        headers=AUTH,
        json={
            "sensitivity": "strict",
            "block_enabled": True,
            "high_risk_min_risk": 2,
        },
    )

    response = client.put(
        "/admin/chats/chat-5/config",
        headers=AUTH,
        json={"reset": True, "block_enabled": True},
    )
    body = response.json()
    assert body["sensitivity"] == "standard"
    assert body["high_risk_min_risk"] is None
    assert body["block_enabled"] is True


def test_set_user_trusted_and_visible_in_listings():
    response = client.put(
        "/admin/users/sender-1/trusted",
        headers=AUTH,
        json={"trusted": True},
    )
    assert response.status_code == 200
    assert response.json() == {"sender": "sender-1", "trusted": True}

    listing = client.get("/admin/users", headers=AUTH)
    assert listing.json()["users"][0]["trusted"] == 1


def test_set_user_trusted_false():
    client.put(
        "/admin/users/sender-2/trusted",
        headers=AUTH,
        json={"trusted": True},
    )
    response = client.put(
        "/admin/users/sender-2/trusted",
        headers=AUTH,
        json={"trusted": False},
    )
    assert response.status_code == 200
    assert response.json()["trusted"] is False

    user = client.get("/admin/users/sender-2", headers=AUTH)
    assert user.json()["user"]["trusted"] == 0


def test_set_user_override():
    response = client.put(
        "/admin/users/sender-3/override",
        headers=AUTH,
        json={"action": "BLOCK"},
    )
    assert response.status_code == 200
    assert response.json()["override_action"] == "BLOCK"

    user = client.get("/admin/users/sender-3", headers=AUTH)
    assert user.json()["user"]["override_action"] == "BLOCK"


def test_set_user_override_to_null_clears_it():
    client.put(
        "/admin/users/sender-4/override",
        headers=AUTH,
        json={"action": "BLOCK"},
    )
    response = client.put(
        "/admin/users/sender-4/override",
        headers=AUTH,
        json={"action": None},
    )
    assert response.status_code == 200
    assert response.json()["override_action"] is None

    user = client.get("/admin/users/sender-4", headers=AUTH)
    assert user.json()["user"]["override_action"] is None


def test_reject_invalid_override_action():
    response = client.put(
        "/admin/users/sender-5/override",
        headers=AUTH,
        json={"action": "DELETE_EVERYTHING"},
    )
    assert response.status_code == 422


def test_trusted_user_skips_moderation_end_to_end():
    client.put(
        "/admin/users/trusted-1/trusted",
        headers=AUTH,
        json={"trusted": True},
    )

    from actions.replies import handle_message

    result = handle_message(
        sender="trusted-1",
        text="Transfer immediately http://192.168.1.1/pay",
        chat_id="chat-admin-1",
    )
    assert result["action"] == "ALLOW"
    assert result["policy"]["rule"] == "trusted_user"


def test_override_block_enforced_end_to_end():
    client.put(
        "/admin/users/banned-1/override",
        headers=AUTH,
        json={"action": "BLOCK"},
    )

    from actions.replies import handle_message

    result = handle_message(
        sender="banned-1",
        text="Hello everyone",
        chat_id="chat-admin-2",
    )
    assert result["action"] == "BLOCK"
    assert result["policy"]["rule"] == "per_user_override"
    assert result["warning"] == ""


def test_approved_members_requires_token():
    response = client.put(
        "/admin/users/sender-ad-1/approved",
        json={"approved": True},
    )
    assert response.status_code == 422


def test_approved_members_add_and_list():
    response = client.put(
        "/admin/users/+15551234567/approved",
        headers=AUTH,
        json={"approved": True},
    )
    assert response.status_code == 200
    assert response.json()["approved"] is True

    listing = client.get("/admin/users/approved", headers=AUTH)
    assert "+15551234567" in listing.json()["approved_members"]


def test_approved_members_remove():
    client.put(
        "/admin/users/sender-ad-2/approved",
        headers=AUTH,
        json={"approved": True},
    )
    response = client.put(
        "/admin/users/sender-ad-2/approved",
        headers=AUTH,
        json={"approved": False},
    )
    assert response.status_code == 200
    assert response.json()["approved"] is False

    listing = client.get("/admin/users/approved", headers=AUTH)
    assert "sender-ad-2" not in listing.json()["approved_members"]