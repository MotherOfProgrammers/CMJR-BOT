import json

import config
from fastapi import APIRouter, Header, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from actions.greetings import welcome_message
from actions.replies import handle_message_full
from commands.engine import handle_command
from database.database import is_processed, record_audit_event
from webhook.errors import webhook_error
from webhook.security import log_security_event
from whatsapp.meta import MetaWhatsAppAdapter, verify_meta_signature
from whatsapp.provider import GenericWhatsAppAdapter
from whatsapp.security import verify_token
from whatsapp.service import process_whatsapp_message
from whatsapp.validation import (
    PayloadValidationError,
    ProviderError,
    UnsupportedMessageTypeError,
    WebhookNoEventError,
)

router = APIRouter()


class MessageRequest(BaseModel):
    sender: str
    text: str = ""
    chat_id: str | None = None
    chat_type: str | None = None
    participant: str | None = None
    message_id: str | None = None
    quoted_message_id: str | None = None
    timestamp: str | None = None
    message_type: str | None = None


async def read_webhook_body_bytes(request: Request) -> bytes:
    max_bytes = config.MAX_PAYLOAD_BYTES

    content_length = request.headers.get("content-length")

    if content_length is not None:
        try:
            if int(content_length) > max_bytes:
                log_security_event(
                    "payload_too_large",
                    status_code=413,
                    error_code="PAYLOAD_TOO_LARGE",
                )
                raise webhook_error(
                    413,
                    "PAYLOAD_TOO_LARGE",
                    f"Request body exceeds the {max_bytes} byte limit",
                )
        except ValueError:
            pass

    data = await request.body()

    if len(data) > max_bytes:
        log_security_event(
            "payload_too_large",
            status_code=413,
            error_code="PAYLOAD_TOO_LARGE",
        )
        raise webhook_error(
            413,
            "PAYLOAD_TOO_LARGE",
            f"Request body exceeds the {max_bytes} byte limit",
        )

    return data


def parse_json_body(data: bytes) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        log_security_event(
            "malformed_json",
            status_code=400,
            error_code="MALFORMED_JSON",
        )
        raise webhook_error(
            400,
            "MALFORMED_JSON",
            "Request body is not valid JSON",
        )


async def read_webhook_body(request: Request) -> dict:
    return parse_json_body(
        await read_webhook_body_bytes(request)
    )


async def process_payload(
    adapter,
    payload: dict,
) -> dict:
    try:
        result = await process_whatsapp_message(
            adapter=adapter,
            payload=payload,
        )
    except UnsupportedMessageTypeError as exc:
        log_security_event(
            "unsupported_payload",
            status_code=415,
            error_code="UNSUPPORTED_TYPE",
        )
        raise webhook_error(
            415,
            "UNSUPPORTED_TYPE",
            str(exc),
        )
    except PayloadValidationError as exc:
        log_security_event(
            "invalid_payload",
            status_code=400,
            error_code="INVALID_PAYLOAD",
        )
        raise webhook_error(
            400,
            "INVALID_PAYLOAD",
            str(exc),
        )
    return result["response"]


@router.get("/whatsapp")
async def verify_whatsapp_webhook(request: Request):
    if config.PROVIDER != "meta":
        raise webhook_error(
            404,
            "NOT_FOUND",
            "Verification endpoint is not enabled",
        )

    mode = request.query_params.get("hub.mode")
    verify_token_value = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")

    if (
        mode == "subscribe"
        and challenge is not None
        and verify_token(verify_token_value, config.META_VERIFY_TOKEN)
    ):
        return PlainTextResponse(challenge, status_code=200)

    log_security_event(
        "webhook_verification_failed",
        status_code=403,
        error_code="VERIFICATION_FAILED",
    )
    raise webhook_error(
        403,
        "VERIFICATION_FAILED",
        "Webhook verification failed",
    )


@router.post("/message")
async def receive_message(
    data: MessageRequest,
    x_webhook_token: str = Header(None),
):
    if not verify_token(x_webhook_token, config.WEBHOOK_TOKEN):
        log_security_event(
            "invalid_authentication",
            status_code=401,
            error_code="UNAUTHORIZED",
        )
        raise webhook_error(
            401,
            "UNAUTHORIZED",
            "Invalid webhook token",
        )

    sender = (data.participant or data.sender or "").strip()
    chat_id = data.chat_id or ""
    text = data.text or ""

    if data.message_type and data.message_type.lower() != "text":
        record_audit_event(
            event_type="non_text_metadata",
            sender=sender,
            chat_id=chat_id or None,
            detail=json.dumps({"message_type": data.message_type}),
        )
        return {
            "status": "metadata",
            "reply": "",
            "action_request": None,
        }

    if chat_id and data.message_id and is_processed(chat_id, data.message_id):
        return {
            "status": "duplicate",
            "reply": "",
            "action_request": None,
        }

    if text.lstrip().lower().startswith("!cmjr"):
        command_result = handle_command(
            text,
            sender,
            chat_id or "default",
            quoted_message_id=data.quoted_message_id,
        )

        if command_result is not None:
            return {
                "status": "command",
                "reply": command_result.get("reply") or "",
                "action_request": command_result.get("action_request"),
            }

    result = await handle_message_full(
        sender=sender,
        text=text,
        chat_id=chat_id or None,
        message_id=data.message_id,
        message_type=data.message_type,
        chat_type=data.chat_type,
    )

    decision = result.get("decision") or {}
    action_request = None

    if decision.get("should_delete") and data.message_id:
        action_request = {
            "action": "DELETE",
            "chat_id": chat_id,
            "target_message_id": data.message_id,
        }

    return {
        "status": result.get("status", "processed"),
        "reply": "",
        "action_request": action_request,
        "sender": result.get("sender", sender),
        "chat_id": result.get("chat_id", chat_id),
        "risk": result.get("risk"),
        "action": result.get("action"),
        "categories": result.get("categories"),
        "ai_used": result.get("ai_used", False),
    }


ACTIVITY_EVENT_TYPES = {
    "messages.upsert",
    "messages.update",
    "messages.delete",
    "group-participants.update",
    "groups.update",
    "presence.update",
    "chats.update",
    "message-receipt.update",
}


@router.post("/activity")
async def receive_activity(
    request: Request,
    x_webhook_token: str = Header(None),
):
    if not verify_token(x_webhook_token, config.WEBHOOK_TOKEN):
        log_security_event(
            "invalid_authentication",
            status_code=401,
            error_code="UNAUTHORIZED",
        )
        raise webhook_error(
            401,
            "UNAUTHORIZED",
            "Invalid webhook token",
        )

    payload = await read_webhook_body(request)
    event_type = payload.get("event_type") or payload.get("type")

    if event_type not in ACTIVITY_EVENT_TYPES:
        return {"status": "ignored"}

    chat_id = payload.get("chat_id") or payload.get("id")

    record_audit_event(
        event_type=f"activity.{event_type}",
        sender=payload.get("sender"),
        chat_id=chat_id,
        detail=json.dumps(
            {
                key: payload[key]
                for key in payload
                if key not in ("event_type", "type", "sender", "chat_id", "id")
            }
        ),
    )

    if (
        event_type == "group-participants.update"
        and payload.get("action") == "add"
        and payload.get("participants")
    ):
        return {
            "status": "accepted",
            "chat_id": chat_id,
            "reply": welcome_message(payload.get("participants")),
        }

    return {"status": "accepted"}


@router.post("/whatsapp")
async def receive_whatsapp_webhook(
    request: Request,
    x_webhook_token: str = Header(None),
):
    if config.PROVIDER == "meta":
        raw_body = await read_webhook_body_bytes(request)

        signature = request.headers.get("x-hub-signature-256")

        if not verify_meta_signature(
            raw_body,
            signature,
            config.META_APP_SECRET,
        ):
            log_security_event(
                "invalid_signature",
                status_code=401,
                error_code="INVALID_SIGNATURE",
            )
            raise webhook_error(
                401,
                "INVALID_SIGNATURE",
                "Webhook signature verification failed",
            )

        payload = parse_json_body(raw_body)

        try:
            result = await process_whatsapp_message(
                adapter=MetaWhatsAppAdapter(),
                payload=payload,
            )
        except WebhookNoEventError:
            return {"status": "accepted"}
        except UnsupportedMessageTypeError:
            log_security_event(
                "unsupported_payload",
                status_code=200,
                error_code="UNSUPPORTED_TYPE",
            )
            return {"status": "accepted"}
        except PayloadValidationError as exc:
            log_security_event(
                "invalid_payload",
                status_code=400,
                error_code="INVALID_PAYLOAD",
            )
            raise webhook_error(
                400,
                "INVALID_PAYLOAD",
                str(exc),
            )
        except ProviderError as exc:
            log_security_event(
                "provider_error",
                status_code=200,
                error_code="PROVIDER_ERROR",
            )
            return {"status": "accepted"}

        return result["response"]

    if not verify_token(x_webhook_token, config.WEBHOOK_TOKEN):
        log_security_event(
            "invalid_authentication",
            status_code=401,
            error_code="UNAUTHORIZED",
        )
        raise webhook_error(
            401,
            "UNAUTHORIZED",
            "Invalid webhook token",
        )

    payload = await read_webhook_body(request)

    return await process_payload(
        GenericWhatsAppAdapter(),
        payload,
    )