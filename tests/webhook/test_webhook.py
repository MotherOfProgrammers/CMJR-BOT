import json

import pytest
from fastapi.testclient import TestClient

from config import WEBHOOK_TOKEN
from main import app

client = TestClient(app, raise_server_exceptions=False)

TOKEN = WEBHOOK_TOKEN


def post_whatsapp(content, token=TOKEN):
    return client.post(
        "/webhook/whatsapp",
        content=content,
        headers={"X-Webhook-Token": token},
    )


def post_whatsapp_json(payload, token=TOKEN):
    return post_whatsapp(json.dumps(payload), token=token)


def test_malformed_json_returns_400():
    response = post_whatsapp("{not valid json")
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "MALFORMED_JSON"
    assert "message" in body


def test_incomplete_json_returns_400():
    response = post_whatsapp("[")
    assert response.status_code == 400


def test_trailing_comma_json_returns_400():
    response = post_whatsapp('{"a": 1,}')
    assert response.status_code == 400


def test_empty_body_returns_400():
    response = post_whatsapp("")
    assert response.status_code == 400


def test_server_stays_healthy_after_malformed_json():
    assert post_whatsapp("{broken").status_code == 400
    assert post_whatsapp("not json at all").status_code == 400
    health = client.get("/")
    assert health.status_code == 200
    assert health.json() == {"status": "online"}


def test_missing_messages_field():
    response = post_whatsapp_json({})
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_PAYLOAD"


def test_empty_messages_list():
    assert post_whatsapp_json({"messages": []}).status_code == 400


def test_empty_message_object():
    assert post_whatsapp_json({"messages": [{}]}).status_code == 400


def test_messages_not_a_list():
    assert post_whatsapp_json({"messages": {"from": "u1"}}).status_code == 400


def test_message_not_an_object():
    assert post_whatsapp_json({"messages": ["hello"]}).status_code == 400


def test_missing_sender():
    assert post_whatsapp_json(
        {"messages": [{"id": "m1", "text": {"body": "hi"}}]}
    ).status_code == 400


def test_missing_text_field():
    assert post_whatsapp_json(
        {"messages": [{"from": "u1", "id": "m1"}]}
    ).status_code == 400


def test_text_wrong_type():
    response = post_whatsapp_json(
        {"messages": [{"from": "u1", "text": "plain string"}]}
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_PAYLOAD"


def test_text_body_wrong_type():
    assert post_whatsapp_json(
        {"messages": [{"from": "u1", "text": {"body": 123}}]}
    ).status_code == 400


def test_whitespace_only_text_rejected():
    assert post_whatsapp_json(
        {"messages": [{"from": "u1", "text": {"body": "   "}}]}
    ).status_code == 400


def test_top_level_json_not_object():
    response = post_whatsapp("[1, 2, 3]")
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_PAYLOAD"


def test_valid_payload_still_processes():
    response = post_whatsapp_json({
        "messages": [
            {
                "from": "user123",
                "id": "msg-001",
                "text": {"body": "Hello from WhatsApp"},
                "chat_id": "chat-001",
            }
        ]
    })
    assert response.status_code == 200
    body = response.json()
    assert {"chat_id", "message_id", "action", "text"} <= set(body.keys())
    assert body["chat_id"] == "chat-001"
    assert body["message_id"] == "msg-001"


def test_server_stays_healthy_after_invalid_payloads():
    payloads = [
        {},
        {"messages": []},
        {"messages": [{}]},
        {"messages": {"from": "u1"}},
    ]
    for payload in payloads:
        assert post_whatsapp_json(payload).status_code == 400
    health = client.get("/")
    assert health.status_code == 200


UNSUPPORTED_TYPES = [
    "image",
    "audio",
    "document",
    "sticker",
    "location",
    "video",
    "contacts",
    "media",
    "poll",
    "reaction",
]


@pytest.mark.parametrize("message_type", UNSUPPORTED_TYPES)
def test_unsupported_message_type_rejected(message_type):
    response = post_whatsapp_json({
        "messages": [
            {
                "from": "user123",
                "id": "msg-001",
                "type": message_type,
                "text": {"body": "not relevant"},
                "chat_id": "chat-001",
            }
        ]
    })
    assert response.status_code == 415
    body = response.json()
    assert body["error"] == "UNSUPPORTED_TYPE"
    assert message_type in body["message"]


def test_unknown_message_type_rejected():
    response = post_whatsapp_json({
        "messages": [
            {
                "from": "user123",
                "id": "msg-001",
                "type": "telepathy",
                "text": {"body": "hello"},
            }
        ]
    })
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_PAYLOAD"


def test_payload_over_limit_rejected(monkeypatch):
    import config
    monkeypatch.setattr(config, "MAX_PAYLOAD_BYTES", 100)
    big_body = json.dumps({
        "messages": [
            {
                "from": "user123",
                "id": "msg-001",
                "text": {"body": "x" * 500},
            }
        ]
    })
    response = post_whatsapp(big_body)
    assert response.status_code == 413
    body = response.json()
    assert body["error"] == "PAYLOAD_TOO_LARGE"
    assert "message" in body


def test_payload_over_limit_leaves_server_healthy(monkeypatch):
    import config
    monkeypatch.setattr(config, "MAX_PAYLOAD_BYTES", 100)
    big_body = json.dumps({
        "messages": [
            {
                "from": "u1",
                "text": {"body": "y" * 500},
            }
        ]
    })
    response = post_whatsapp(big_body)
    assert response.status_code == 413
    health = client.get("/")
    assert health.status_code == 200


def _assert_consistent_error(response):
    body = response.json()
    assert isinstance(body, dict)
    assert set(body.keys()) == {"error", "message"}
    assert "detail" not in body
    assert "Traceback" not in response.text
    assert "traceback" not in body


def test_missing_token_returns_401():
    response = client.post("/webhook/whatsapp", content="{}")
    assert response.status_code == 401
    _assert_consistent_error(response)


def test_all_error_paths_use_consistent_shape(monkeypatch):
    import config
    monkeypatch.setattr(config, "MAX_PAYLOAD_BYTES", 100)
    big_body = json.dumps({
        "messages": [
            {
                "from": "u1",
                "text": {"body": "z" * 300},
            }
        ]
    })

    cases = [
        (post_whatsapp("{broken"), 400),
        (post_whatsapp_json({}), 400),
        (post_whatsapp(big_body), 413),
        (post_whatsapp_json({
            "messages": [
                {"from": "u1", "type": "image", "text": {"body": "x"}},
            ]
        }), 415),
        (post_whatsapp("{}", token="wrong-token"), 401),
        (client.post(
            "/webhook/whatsapp",
            content=json.dumps({
                "messages": [
                    {"from": "u1", "id": "m1", "text": {"body": "hello"}},
                ]
            }),
        ), 401),
    ]

    for response, expected_status in cases:
        assert response.status_code == expected_status, response.text
        _assert_consistent_error(response)


def test_no_server_traceback_leaks():
    response = post_whatsapp("{broken")
    assert response.status_code == 400
    _assert_consistent_error(response)


def test_security_events_are_logged(caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="cmjr.security"):
        post_whatsapp("{broken")
        post_whatsapp_json({})
        post_whatsapp("{}", token="wrong-token")
        post_whatsapp_json(
            {"messages": [{"from": "u1", "type": "image"}]}
        )
    text = caplog.text
    assert "invalid_authentication" in text
    assert "malformed_json" in text
    assert "invalid_payload" in text
    assert "unsupported_payload" in text


def test_request_content_is_not_logged(caplog):
    import logging
    secret = "SUPER-SECRET-MARKER"
    secret_payload = json.dumps({"messages": [{"from": "u1", "text": {"body": secret}}]})
    with caplog.at_level(logging.WARNING, logger="cmjr.security"):
        assert post_whatsapp(secret_payload).status_code == 200
        assert post_whatsapp(secret_payload, token="wrong").status_code == 401
    assert secret not in caplog.text