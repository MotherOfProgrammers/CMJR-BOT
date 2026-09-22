import asyncio
import hashlib
import hmac

import httpx
import pytest

from whatsapp.meta import (
    MetaWhatsAppAdapter,
    NON_TEXT_MESSAGE_TYPES,
    verify_meta_signature,
)
from whatsapp.validation import (
    PayloadValidationError,
    ProviderError,
    UnsupportedMessageTypeError,
    WebhookNoEventError,
)

APP_SECRET = "test_app_secret"

TEXT_PAYLOAD = {
    "object": "whatsapp_business_account",
    "entry": [
        {
            "id": "102290129340398",
            "changes": [
                {
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15550783881",
                            "phone_number_id": "106540352242922",
                        },
                        "contacts": [
                            {
                                "profile": {"name": "Sheena Nelson"},
                                "wa_id": "16505551234",
                            }
                        ],
                        "messages": [
                            {
                                "from": "16505551234",
                                "id": "wamid.HBgLMTY1MDM4Nzk0MzkVAgASGAk=",
                                "timestamp": "1749416383",
                                "type": "text",
                                "text": {"body": "Does it come in another color?"},
                            }
                        ],
                    },
                    "field": "messages",
                }
            ],
        }
    ],
}

STATUS_PAYLOAD = {
    "object": "whatsapp_business_account",
    "entry": [
        {
            "id": "102290129340398",
            "changes": [
                {
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
                    "field": "messages",
                }
            ],
        }
    ],
}


def meta_signature(raw_body: bytes, secret: str) -> str:
    digest = hmac.new(
        secret.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def make_adapter(client=None, **kwargs):
    params = {
        "access_token": "test-access-token",
        "phone_number_id": "106540352242922",
        "api_version": "v1.0",
        "graph_url": "https://graph.test",
        "client": client,
    }
    params.update(kwargs)
    return MetaWhatsAppAdapter(**params)


class FakeResponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data or {}

    def json(self):
        return self._data


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def post(self, url, headers=None, json=None):
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "json": json,
            }
        )
        return self.response


def test_verify_meta_signature_valid():
    raw = b'{"hello": "world"}'
    assert verify_meta_signature(
        raw,
        meta_signature(raw, APP_SECRET),
        APP_SECRET,
    ) is True


def test_verify_meta_signature_invalid():
    raw = b'{"hello": "world"}'
    assert verify_meta_signature(
        raw,
        "sha256=" + "0" * 64,
        APP_SECRET,
    ) is False


def test_verify_meta_signature_missing_header():
    assert verify_meta_signature(
        b"body",
        None,
        APP_SECRET,
    ) is False


def test_verify_meta_signature_wrong_prefix():
    assert verify_meta_signature(
        b"body",
        "md5=" + "0" * 64,
        APP_SECRET,
    ) is False


def test_verify_meta_signature_empty_secret():
    assert verify_meta_signature(
        b"body",
        "sha256=" + "0" * 64,
        None,
    ) is False


def test_parse_text_message():
    message = make_adapter().parse_message(TEXT_PAYLOAD)
    assert message.sender == "16505551234"
    assert message.text == "Does it come in another color?"
    assert message.message_id == "wamid.HBgLMTY1MDM4Nzk0MzkVAgASGAk="
    assert message.chat_id == "16505551234"
    assert message.recipient_type == "individual"


def test_parse_group_message():
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {"phone_number_id": "106540352242922"},
                            "contacts": [
                                {"profile": {"name": "Nina"}, "wa_id": "16505551234"}
                            ],
                            "messages": [
                                {
                                    "from": "16505551234",
                                    "group_id": "Y2FwaV9ncm91cDoxNw==",
                                    "id": "wamid.group",
                                    "timestamp": "1750000000",
                                    "type": "text",
                                    "text": {"body": "hello group"},
                                }
                            ],
                        },
                    }
                ]
            }
        ],
    }
    message = make_adapter().parse_message(payload)
    assert message.chat_id == "Y2FwaV9ncm91cDoxNw=="
    assert message.recipient_type == "group"
    assert message.sender == "16505551234"


@pytest.mark.parametrize(
    "message_type",
    ["image", "audio", "video", "document", "sticker", "location", "contacts"],
)
def test_non_text_type_raises_unsupported(message_type):
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {"phone_number_id": "p"},
                            "contacts": [{"wa_id": "16505551234"}],
                            "messages": [
                                {
                                    "from": "16505551234",
                                    "id": "wamid.media",
                                    "timestamp": "1750000000",
                                    "type": message_type,
                                }
                            ],
                        },
                    }
                ]
            }
        ],
    }
    with pytest.raises(UnsupportedMessageTypeError):
        make_adapter().parse_message(payload)


def test_statuses_only_raises_webhook_no_event():
    with pytest.raises(WebhookNoEventError):
        make_adapter().parse_message(STATUS_PAYLOAD)


def test_wrong_object_raises():
    payload = {"object": "other", "entry": []}
    with pytest.raises(PayloadValidationError):
        make_adapter().parse_message(payload)


def test_missing_messages_raises():
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "changes": [
                    {
                        "field": "messages",
                        "value": {"messaging_product": "whatsapp"},
                    }
                ]
            }
        ],
    }
    with pytest.raises(PayloadValidationError):
        make_adapter().parse_message(payload)


def test_unknown_message_type_raises():
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [
                                {
                                    "from": "16505551234",
                                    "id": "wamid.x",
                                    "type": "telepathy",
                                }
                            ],
                        },
                    }
                ]
            }
        ],
    }
    with pytest.raises(PayloadValidationError):
        make_adapter().parse_message(payload)


def test_send_message_builds_request():
    fake = FakeClient(FakeResponse(200, {"messages": [{"id": "wamid.out"}]}))
    adapter = make_adapter(client=fake)
    result = asyncio.run(
        adapter.send_message(
            chat_id="+16505551234",
            text="Hello there",
            recipient_type="individual",
        )
    )

    call = fake.calls[0]
    assert call["url"] == "https://graph.test/v1.0/106540352242922/messages"
    assert call["headers"]["Authorization"] == "Bearer test-access-token"
    assert call["json"] == {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": "+16505551234",
        "type": "text",
        "text": {"body": "Hello there"},
    }
    assert result["status_code"] == 200


def test_send_group_message():
    fake = FakeClient(FakeResponse(200, {}))
    adapter = make_adapter(client=fake)
    asyncio.run(
        adapter.send_message(
            chat_id="Y2FwaV9ncm91cDoxNw==",
            text="Hello group",
            recipient_type="group",
        )
    )
    assert fake.calls[0]["json"]["recipient_type"] == "group"
    assert fake.calls[0]["json"]["to"] == "Y2FwaV9ncm91cDoxNw=="


def test_send_message_api_error_raises():
    error_payload = {
        "error": {
            "message": "(#130429) Rate limit hit",
            "type": "OAuthException",
            "code": 130429,
        }
    }
    fake = FakeClient(FakeResponse(400, error_payload))
    adapter = make_adapter(client=fake)
    with pytest.raises(ProviderError) as exc_info:
        asyncio.run(
            adapter.send_message(chat_id="+16505551234", text="x")
        )
    assert "130429" in str(exc_info.value)


def test_send_message_requires_credentials():
    fake = FakeClient(FakeResponse(200, {}))
    adapter = make_adapter(client=fake, access_token=None, phone_number_id=None)
    with pytest.raises(ProviderError):
        asyncio.run(
            adapter.send_message(chat_id="+16505551234", text="x")
        )
    assert fake.calls == []


def test_send_message_with_real_async_client():
    requested = {}

    async def handler(request):
        requested["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"messages": [{"id": "wamid.ok"}]},
        )

    async_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    )
    adapter = MetaWhatsAppAdapter(
        access_token="test-access-token",
        phone_number_id="106540352242922",
        api_version="v1.0",
        graph_url="https://graph.test",
        client=async_client,
    )

    result = asyncio.run(
        adapter.send_message(
            chat_id="+16505551234",
            text="Hello async",
            recipient_type="individual",
        )
    )

    assert result["status_code"] == 200
    assert "106540352242922/messages" in requested["url"]


def test_non_text_types_set_is_populated():
    assert "text" not in NON_TEXT_MESSAGE_TYPES
    assert "image" in NON_TEXT_MESSAGE_TYPES