from starlette.testclient import TestClient

from main import app


client = TestClient(app)


def test_image_message_metadata_only(webhook_headers):
    response = client.post(
        "/webhook/message",
        json={
            "sender": "pic-user",
            "text": "",
            "chat_id": "g-img",
            "message_id": "m1",
            "message_type": "image",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "metadata"
    assert body["reply"] == ""


def test_duplicate_message_id_skipped(webhook_headers):
    payload = {
        "sender": "dup-user",
        "text": "First copy",
        "chat_id": "g-dup",
        "message_id": "dup-1",
    }

    first = client.post("/webhook/message", json=payload, headers=webhook_headers)
    assert first.status_code == 200
    assert first.json()["status"] == "processed"

    second = client.post("/webhook/message", json=payload, headers=webhook_headers)
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"


def test_activity_welcomes_participant_join(webhook_headers):
    response = client.post(
        "/webhook/activity",
        json={
            "event_type": "group-participants.update",
            "id": "g-act",
            "action": "add",
            "participants": ["new-user@c.us"],
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert body["chat_id"] == "g-act"
    assert "Welcome" in body["reply"]


def test_activity_does_not_welcome_participant_leave(webhook_headers):
    response = client.post(
        "/webhook/activity",
        json={
            "event_type": "group-participants.update",
            "id": "g-act",
            "action": "remove",
            "participants": ["left-user@c.us"],
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert "reply" not in response.json()


def test_activity_accepts_participant_leave(webhook_headers):
    response = client.post(
        "/webhook/activity",
        json={
            "event_type": "group-participants.update",
            "id": "g-act",
            "action": "remove",
            "participants": ["left-user@c.us"],
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_activity_accepts_messages_upsert(webhook_headers):
    response = client.post(
        "/webhook/activity",
        json={"event_type": "messages.upsert", "id": "g-act"},
        headers=webhook_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_activity_ignores_unknown_event_type(webhook_headers):
    response = client.post(
        "/webhook/activity",
        json={"event_type": "something.else", "id": "g-x"},
        headers=webhook_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_malformed_message_rejected(webhook_headers):
    response = client.post(
        "/webhook/message",
        json={"no_sender_here": True, "text": "x"},
        headers=webhook_headers,
    )
    assert response.status_code == 400


def test_invalid_webhook_token_rejected():
    response = client.post(
        "/webhook/message",
        json={"sender": "u", "text": "hello"},
        headers={"X-Webhook-Token": "wrong-token"},
    )
    assert response.status_code == 401


def test_missing_webhook_token_rejected():
    response = client.post(
        "/webhook/message",
        json={"sender": "u", "text": "hello"},
    )
    assert response.status_code == 401


def test_normal_message_via_webhook(webhook_headers):
    response = client.post(
        "/webhook/message",
        json={
            "sender": "w-user",
            "text": "Good morning",
            "chat_id": "g-web",
            "message_id": "m-web-1",
            "chat_type": "group",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "processed"
    assert body["action"] == "ALLOW"
    assert body["reply"] == ""
    assert "text" not in body


def test_flagged_message_stays_silent_on_chat(webhook_headers, monkeypatch):
    monkeypatch.setattr("config.AUTO_DELETE", False)

    response = client.post(
        "/webhook/message",
        json={
            "sender": "w-user",
            "text": "Login now http://192.168.1.1/login",
            "chat_id": "g-web",
            "message_id": "m-web-2",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["reply"] == ""
    assert body["action_request"] is None


def test_unapproved_link_deleted_when_auto_delete_on(webhook_headers, monkeypatch):
    monkeypatch.setattr("config.AUTO_DELETE", True)

    response = client.post(
        "/webhook/message",
        json={
            "sender": "del-user",
            "text": "Check this out https://bit.ly/erpxkg",
            "chat_id": "g-del",
            "message_id": "m-del-1",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["action_request"] == {
        "action": "DELETE",
        "chat_id": "g-del",
        "target_message_id": "m-del-1",
    }


def test_unapproved_link_not_deleted_when_auto_delete_off(webhook_headers, monkeypatch):
    monkeypatch.setattr("config.AUTO_DELETE", False)

    response = client.post(
        "/webhook/message",
        json={
            "sender": "del-user",
            "text": "Check this out https://bit.ly/erpxkg",
            "chat_id": "g-del",
            "message_id": "m-del-0",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["action_request"] is None


def test_approved_member_link_not_deleted(webhook_headers, monkeypatch):
    from database.database import add_approved_member

    monkeypatch.setattr("config.AUTO_DELETE", True)
    add_approved_member("approved-1")

    response = client.post(
        "/webhook/message",
        json={
            "sender": "approved-1",
            "text": "Check this out https://bit.ly/erpxkg",
            "chat_id": "g-del",
            "message_id": "m-del-4",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] in {"ALLOW", "REVIEW", "LOG"}
    assert body["action_request"] is None


def test_approved_member_harmful_content_still_deleted(webhook_headers, monkeypatch):
    from database.database import add_approved_member

    monkeypatch.setattr("config.AUTO_DELETE", True)
    add_approved_member("approved-2")

    response = client.post(
        "/webhook/message",
        json={
            "sender": "approved-2",
            "text": "Your mother should be ashamed",
            "chat_id": "g-del",
            "message_id": "m-del-5",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["categories"] == ["HARASSMENT"]
    assert body["action_request"] == {
        "action": "DELETE",
        "chat_id": "g-del",
        "target_message_id": "m-del-5",
    }


def test_auto_delete_per_chat_override(webhook_headers, monkeypatch):
    from database.database import save_chat_config

    from policy.models import ChatConfig

    monkeypatch.setattr("config.AUTO_DELETE", False)
    chat = ChatConfig(chat_id="g-del2")
    chat.auto_delete = True
    save_chat_config(chat)

    response = client.post(
        "/webhook/message",
        json={
            "sender": "del-user",
            "text": "Login now http://192.168.1.1/login",
            "chat_id": "g-del2",
            "message_id": "m-del-2",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["action_request"] is not None
    assert body["action_request"]["target_message_id"] == "m-del-2"


def test_plain_suspicious_link_still_reviewed_for_approved(webhook_headers, monkeypatch):
    from database.database import add_approved_member

    monkeypatch.setattr("config.AUTO_DELETE", True)
    add_approved_member("approved-3")

    response = client.post(
        "/webhook/message",
        json={
            "sender": "approved-3",
            "text": "Check http://bit.ly/xyz",
            "chat_id": "g-del",
            "message_id": "m-del-6",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "REVIEW"
    assert body["action_request"] is None


def test_adult_link_deleted_even_when_approved(webhook_headers, monkeypatch):
    from database.database import add_approved_member

    monkeypatch.setattr("config.AUTO_DELETE", True)
    add_approved_member("approved-adult-1")

    response = client.post(
        "/webhook/message",
        json={
            "sender": "approved-adult-1",
            "text": "Onlyfans promo: https://onlyfans.com/model/fan",
            "chat_id": "g-adult",
            "message_id": "m-adult-1",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "DELETE"
    assert body["categories"] == ["ADULT"]
    assert body["action_request"] == {
        "action": "DELETE",
        "chat_id": "g-adult",
        "target_message_id": "m-adult-1",
    }


def test_command_via_webhook(webhook_headers):
    from database.database import set_user_role

    set_user_role("w-admin", "admin")

    response = client.post(
        "/webhook/message",
        json={
            "sender": "w-admin",
            "text": "!cmjr status",
            "chat_id": "g-web",
        },
        headers=webhook_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "command"
    assert "Status" in body["reply"]


def test_bridge_skips_own_messages_by_design():
    source = open("whatsapp-bridge/index.js").read()
    assert 'msg.key?.fromMe' in source


def test_bridge_welcomes_new_members_by_design():
    source = open("whatsapp-bridge/index.js").read()
    assert 'action === "add"' in source
    assert "Sending welcome" in source