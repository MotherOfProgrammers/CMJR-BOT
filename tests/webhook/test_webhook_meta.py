import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import config
from main import app

client = TestClient(app, raise_server_exceptions=False)


def meta_signature(raw_body, secret):
    digest = hmac.new(
        secret.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def meta_payload(body):
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "102290129340398",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "15550783881",
                                "phone_number_id": "106540352242922",
                            },
                            "contacts": [
                                {"profile": {"name": "Sheena"}, "wa_id": "16505551234"}
                            ],
                            "messages": [
                                {
                                    "from": "16505551234",
                                    "id": "wamid.route",
                                    "timestamp": "1749416383",
                                    **body,
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }


def enable_meta(monkeypatch):
    monkeypatch.setattr(config, "PROVIDER", "meta")
    monkeypatch.setattr(config, "META_APP_SECRET", "route-app-secret")
    monkeypatch.setattr(config, "META_VERIFY_TOKEN", "route-verify-token")
    monkeypatch.setattr(config, "META_ACCESS_TOKEN", "route-access-token")
    monkeypatch.setattr(config, "META_PHONE_NUMBER_ID", "106540352242922")


def test_get_verification_returns_challenge(monkeypatch):
    enable_meta(monkeypatch)
    response = client.get(
        "/webhook/whatsapp",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "route-verify-token",
            "hub.challenge": "1158201444",
        },
    )
    assert response.status_code == 200
    assert response.text == "1158201444"


def test_get_verification_wrong_token_rejected(monkeypatch):
    enable_meta(monkeypatch)
    response = client.get(
        "/webhook/whatsapp",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "wrong",
            "hub.challenge": "1158201444",
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "VERIFICATION_FAILED"


def test_get_verification_disabled_in_generic_mode():
    assert config.PROVIDER != "meta"
    response = client.get("/webhook/whatsapp")
    assert response.status_code == 404


def test_post_processes_text_message_with_valid_signature(monkeypatch):
    enable_meta(monkeypatch)
    payload = meta_payload({"type": "text", "text": {"body": "Hello everyone!"}})
    raw = json.dumps(payload).encode()
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "route-app-secret")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["chat_id"] == "16505551234"
    assert body["message_id"] == "wamid.route"
    assert body["action"] in {"ALLOW", "REVIEW", "HIGH_RISK"}


def test_post_rejects_invalid_signature(monkeypatch):
    enable_meta(monkeypatch)
    payload = meta_payload({"type": "text", "text": {"body": "Hello"}})
    raw = json.dumps(payload).encode()
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "wrong-secret")},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "INVALID_SIGNATURE"


def test_post_rejects_missing_signature(monkeypatch):
    enable_meta(monkeypatch)
    raw = json.dumps(meta_payload({"type": "text", "text": {"body": "Hello"}})).encode()
    response = client.post("/webhook/whatsapp", content=raw)
    assert response.status_code == 401
    assert response.json()["error"] == "INVALID_SIGNATURE"


def test_post_acknowledges_non_text_message(monkeypatch):
    enable_meta(monkeypatch)
    payload = meta_payload({"type": "image", "image": {"id": "abc", "mime_type": "image/jpeg"}})
    raw = json.dumps(payload).encode()
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "route-app-secret")},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}


def test_post_acknowledges_statuses_only(monkeypatch):
    enable_meta(monkeypatch)
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "102290129340398",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "15550783881",
                                "phone_number_id": "106540352242922",
                            },
                            "statuses": [
                                {
                                    "id": "wamid.status",
                                    "status": "delivered",
                                    "timestamp": "1750263773",
                                    "recipient_id": "16505551234",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }
    raw = json.dumps(payload).encode()
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "route-app-secret")},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}


def test_post_invalid_text_structure_rejected(monkeypatch):
    enable_meta(monkeypatch)
    payload = meta_payload({"type": "text", "text": {"body": ""}})
    raw = json.dumps(payload).encode()
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "route-app-secret")},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_PAYLOAD"


def test_post_malformed_json_with_valid_signature_rejected(monkeypatch):
    enable_meta(monkeypatch)
    raw = b"{not valid json"
    response = client.post(
        "/webhook/whatsapp",
        content=raw,
        headers={"X-Hub-Signature-256": meta_signature(raw, "route-app-secret")},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "MALFORMED_JSON"