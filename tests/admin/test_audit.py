import pytest
from fastapi.testclient import TestClient

from config import ADMIN_TOKEN
from database.database import (
    get_audit_events,
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


def test_message_decision_is_audited():
    from actions.replies import handle_message

    handle_message(
        sender="audited-1",
        text="Claim your prize http://bit.ly/x",
        chat_id="chat-audit-1",
    )

    events = get_audit_events()
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "policy_decision"
    assert event["sender"] == "audited-1"
    assert event["chat_id"] == "chat-audit-1"
    assert event["risk"] is not None
    assert event["action"] in {"ALLOW", "REVIEW", "HIGH_RISK", "WARN", "DELETE"}
    assert event["rule"] in {
        "allow",
        "review",
        "high_risk",
        "warn_borderline",
        "escalate_serial",
        "escalate_high_serial",
        "trusted_user",
        "per_user_override",
        "block_high_risk",
        "chat_disabled",
        "toxicity_detected",
        "harassment_detected",
        "threat_detected",
        "ai_threat_advisory",
        "link_log_unknown",
        "link_review_unknown",
        "link_block_suspicious",
        "link_block_external",
        "link_allow_trusted_only",
        "link_sender_not_approved",
    }
    assert event["warning_count"] == 0
    assert event["trusted"] == 0


def test_audit_records_decision_inputs_for_escalation():
    from actions.replies import handle_message

    for _ in range(5):
        handle_message(
            sender="serial-1",
            text="Claim your prize money now",
            chat_id="chat-audit-2",
        )

    events = get_audit_events(limit=1)
    assert events[0]["sender"] == "serial-1"
    assert events[0]["warning_count"] == 3
    assert events[0]["rule"] in {
        "escalate_serial",
        "escalate_high_serial",
    }
    assert events[0]["action"] == "ESCALATE"


def test_chat_config_admin_change_is_audited():
    client.put(
        "/admin/chats/audit-chat/config",
        headers=AUTH,
        json={"sensitivity": "strict", "block_enabled": True},
    )

    events = get_audit_events(event_type="admin_chat_config")
    assert len(events) == 1
    event = events[0]
    assert event["chat_id"] == "audit-chat"
    assert "sensitivity" in event["detail"]


def test_user_trusted_change_is_audited():
    client.put(
        "/admin/users/audit-user/trusted",
        headers=AUTH,
        json={"trusted": True},
    )

    events = get_audit_events(event_type="admin_user_trusted")
    assert len(events) == 1
    assert events[0]["sender"] == "audit-user"
    assert events[0]["detail"] == '{"trusted": true}'


def test_user_override_change_is_audited():
    client.put(
        "/admin/users/audit-user/override",
        headers=AUTH,
        json={"action": "BLOCK"},
    )

    events = get_audit_events(event_type="admin_user_override")
    assert len(events) == 1
    assert events[0]["sender"] == "audit-user"
    assert events[0]["detail"] == '{"action": "BLOCK"}'


def test_audit_endpoint_requires_token():
    response = client.get("/admin/audit")
    assert response.status_code != 200

    response = client.get("/admin/audit", headers={"X-Admin-Token": "nope"})
    assert response.status_code == 401


def test_audit_endpoint_lists_events_newest_first():
    from actions.replies import handle_message

    handle_message(sender="a-1", text="Hello", chat_id="cha")
    handle_message(sender="a-2", text="Hello", chat_id="chb")

    response = client.get("/admin/audit", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["audit"][0]["sender"] == "a-2"


def test_audit_endpoint_filters_by_sender():
    from actions.replies import handle_message

    handle_message(sender="f-1", text="Hello", chat_id="c1")
    handle_message(sender="f-2", text="Hello", chat_id="c2")

    response = client.get("/admin/audit", headers=AUTH, params={"sender": "f-1"})
    body = response.json()
    assert body["count"] == 1
    assert body["audit"][0]["sender"] == "f-1"


def test_audit_endpoint_filters_by_rule():
    from actions.replies import handle_message

    handle_message(sender="r-1", text="Hello", chat_id="c1")
    handle_message(
        sender="r-2",
        text="Go to http://192.168.1.1/pay now",
        chat_id="c2",
    )

    response = client.get("/admin/audit", headers=AUTH, params={"rule": "allow"})
    body = response.json()
    assert body["count"] == 1
    assert body["audit"][0]["rule"] == "allow"


def test_audit_limit_is_respected():
    from actions.replies import handle_message

    for i in range(5):
        handle_message(sender=f"lim-{i}", text="Hello", chat_id="c")

    assert len(get_audit_events(limit=2)) == 2
    assert len(get_audit_events(limit=2000)) == 5
    assert len(get_audit_events(limit=0)) == 1