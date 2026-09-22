from database.database import set_user_role
from actions.replies import handle_message
from ai.parsers import normalize
from decision.engine import evaluate_message
from moderation.rules import analyze_message
from policy.models import BLOCK, DELETE, REVIEW, ALLOW, ChatConfig


def _decision(sender, text, ai=None, chat=None):
    analysis = analyze_message(sender, text, chat_id="ai-c1")

    return evaluate_message(
        analysis=analysis,
        toxicity=None,
        behavior=None,
        ai=ai,
        chat_config=chat or ChatConfig(chat_id="ai-c1"),
        sender=sender,
        chat_id="ai-c1",
    )


def test_ai_none_provider_falls_back_to_deterministic():
    result = handle_message(sender="ai-1", text="Hello", chat_id="a-c")
    assert result["ai_used"] is False
    assert result["action"] == ALLOW


def test_ai_parse_rejects_garbage():
    assert normalize("not a dict") is None
    assert normalize({}) is None
    assert normalize({"categories": [123]}) is None


def test_ai_parse_clamps_and_whitelists():
    parsed = normalize(
        {
            "categories": ["THREAT", "MADE_UP"],
            "toxicity": 1.9,
            "spam": -3,
            "confidence": 0.99,
            "suggested_action": "BAN_NOW",
            "reason": "x",
        }
    )
    assert parsed["categories"] == ["THREAT"]
    assert parsed["toxicity"] == 1.0
    assert parsed["spam"] == 0.0
    assert parsed["suggested_action"] == ""


def test_ai_threat_advisory_escalates_review():
    ai = {
        "categories": ["THREAT"],
        "confidence": 0.9,
        "toxicity": 0.8,
        "spam": 0.0,
        "suggested_action": "BLOCK",
        "reason": "advisory only",
    }

    decision = _decision("ai-2", "hello", ai=ai)
    assert decision["action"] == REVIEW
    assert decision["ai_used"] is True


def test_ai_multilingual_toxic_deleted():
    ai = {
        "categories": ["TOXIC"],
        "confidence": 0.9,
        "toxicity": 0.85,
        "spam": 0.0,
        "suggested_action": "",
        "reason": "profanity detected in non-English text",
        "language": "es",
    }

    decision = _decision("ai-4", "mierda inútil", ai=ai)
    assert decision["action"] == DELETE
    assert decision["ai_used"] is True
    assert decision["ai_advisory"]["language"] == "es"


def test_ai_low_confidence_toxic_only_reviews():
    ai = {
        "categories": ["TOXIC"],
        "confidence": 0.5,
        "toxicity": 0.9,
        "spam": 0.0,
        "suggested_action": "",
        "reason": "unsure",
    }

    decision = _decision("ai-5", "una frase rara", ai=ai)
    assert decision["action"] == ALLOW


def test_ai_high_toxicity_without_category_not_deleted():
    ai = {
        "categories": [],
        "confidence": 0.95,
        "toxicity": 0.9,
        "spam": 0.0,
        "suggested_action": "",
        "reason": "neutral",
    }

    decision = _decision("ai-6", "hola", ai=ai)
    assert decision["action"] == ALLOW


def test_ai_parse_extracts_language():
    parsed = normalize(
        {
            "categories": ["TOXIC"],
            "toxicity": 0.8,
            "confidence": 0.9,
            "language": "fr-CA",
        }
    )
    assert parsed["language"] == "fr-ca"

    parsed = normalize(
        {
            "categories": ["SAFE"],
            "toxicity": 0.0,
            "confidence": 0.9,
            "language": "not-a-language",
        }
    )
    assert parsed["language"] == ""


def test_ai_parse_extracts_translation():
    parsed = normalize(
        {
            "categories": ["TOXIC"],
            "toxicity": 0.9,
            "confidence": 0.9,
            "language": "si",
            "translation": "you are a stupid donkey",
        }
    )
    assert parsed["translation"] == "you are a stupid donkey"


def test_ai_multilingual_adult_deleted():
    ai = {
        "categories": ["ADULT"],
        "confidence": 0.9,
        "toxicity": 0.8,
        "spam": 0.0,
        "suggested_action": "",
        "reason": "adult content in non-English text",
        "language": "ja",
        "translation": "watch this ecchi clip",
    }

    decision = _decision("ai-7", "このエッチ動画を見て", ai=ai)
    assert decision["action"] == DELETE
    assert decision["ai_used"] is True
    assert decision["ai_advisory"]["language"] == "ja"


def test_system_prompt_is_multilingual():
    from ai.providers import SUPPORTED_LANGUAGES, SYSTEM_PROMPT

    assert "Sinhala" in SUPPORTED_LANGUAGES
    assert "ADULT" in SYSTEM_PROMPT
    assert "language" in SYSTEM_PROMPT and "translation" in SYSTEM_PROMPT


def test_ai_never_authoritative_for_clean_message():
    ai = {
        "categories": [],
        "confidence": 0.2,
        "toxicity": 0.1,
        "spam": 0.0,
        "suggested_action": "BLOCK",
        "reason": "low confidence noise",
    }

    decision = _decision("ai-3", "Hello everyone", ai=ai)
    assert decision["action"] == ALLOW


def test_ai_test_connection_unreachable_when_none(monkeypatch):
    import asyncio

    from ai.providers import test_connection

    monkeypatch.setattr("ai.providers.AI_PROVIDER", "none")

    status = asyncio.run(test_connection())
    assert status["provider"] == "none"
    assert status["reachable"] is False


def test_unauthorized_delete_command_denied():
    from actions.replies import handle_message as _unused  # noqa: F401
    from commands.engine import handle_command

    reply = handle_command("!cmjr delete", "normal-user", "cmd-c1")
    assert reply["reply"] == "Permission denied."
    assert reply["action_request"] is None


def test_authorized_delete_command_executes():
    from commands.engine import handle_command

    set_user_role("mod-1", "moderator")

    reply = handle_command(
        "!cmjr delete",
        "mod-1",
        "cmd-c2",
        quoted_message_id="abc123",
    )
    assert reply["reply"] == "Message deleted."
    assert reply["action_request"] == {
        "action": "DELETE",
        "chat_id": "cmd-c2",
        "target_message_id": "abc123",
    }


def test_authorized_block_command_targets_user():
    from commands.engine import handle_command

    set_user_role("admin-1", "admin")

    reply = handle_command("!cmjr block @banned-2", "admin-1", "cmd-c3")
    assert "blocked" in reply["reply"]


def test_trusted_sender_skips_link_blocking():
    from database.database import set_user_flag

    set_user_flag("link-user", "can_send_links", True)

    result = handle_message(
        sender="link-user",
        text="Share http://192.168.1.1/pay now",
        chat_id="a-c2",
    )
    assert result["policy"]["link_verdict"] is None


def test_link_policy_block_suspicious_blocks():
    from database.database import add_approved_member
    from policy.models import SENSITIVITY_STANDARD

    add_approved_member("linker-1")

    chat = ChatConfig(chat_id="a-c3", link_policy="BLOCK_SUSPICIOUS")
    chat.sensitivity = SENSITIVITY_STANDARD

    decision = _decision("linker-1", "http://bit.ly/aaa", chat=chat)
    assert decision["action"] == BLOCK
    assert decision["link_verdict"]["worst_class"] == "SUSPICIOUS"