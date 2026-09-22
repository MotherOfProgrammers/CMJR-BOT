import pytest

from actions.replies import handle_message
from actions.warning import warning_message
from database.database import (
    get_chat_config,
    get_connection,
    get_user,
    initialize_database,
    save_chat_config,
    set_user_override,
    set_user_trusted,
)
from policy.models import (
    ALLOW,
    BLOCK,
    DELETE,
    ESCALATE,
    HIGH_RISK,
    REVIEW,
    WARN,
    ChatConfig,
    PolicyContext,
    SENSITIVITY_LENIENT,
    SENSITIVITY_STANDARD,
    SENSITIVITY_STRICT,
)
from policy.policy import apply_policy


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


def context(
    risk,
    warnings=0,
    trusted=False,
    override_action=None,
    chat=None,
    chat_id="test-chat",
):
    return PolicyContext(
        risk=risk,
        sender="sender-1",
        chat_id=chat_id,
        warning_count=warnings,
        trusted=trusted,
        override_action=override_action,
        chat=chat,
    )


def test_fresh_user_risk_zero_yields_allow():
    decision = apply_policy(context(risk=0))
    assert decision.action == ALLOW
    assert decision.rule == "allow"


def test_fresh_user_risk_two_yields_review():
    decision = apply_policy(context(risk=2))
    assert decision.action == REVIEW
    assert decision.rule == "review"


def test_fresh_user_risk_four_yields_high_risk():
    decision = apply_policy(context(risk=4))
    assert decision.action == HIGH_RISK
    assert decision.rule == "high_risk"


def test_borderline_risk_one_with_warnings_yields_warn():
    decision = apply_policy(context(risk=1, warnings=3))
    assert decision.action == WARN
    assert decision.rule == "warn_borderline"


def test_borderline_risk_one_without_warnings_yields_allow():
    decision = apply_policy(context(risk=1))
    assert decision.action == ALLOW


def test_escalate_serial_on_repeat_offender():
    decision = apply_policy(context(risk=1, warnings=5))
    assert decision.action == ESCALATE
    assert decision.rule == "escalate_serial"


def test_escalate_high_serial_on_repeat_high_risk():
    decision = apply_policy(context(risk=3, warnings=3))
    assert decision.action == ESCALATE
    assert decision.rule == "escalate_high_serial"


def test_escalate_rule_takes_priority_over_high_risk():
    decision = apply_policy(context(risk=4, warnings=5))
    assert decision.action == ESCALATE
    assert decision.rule == "escalate_serial"


def test_clean_message_never_escalates_despite_history():
    decision = apply_policy(context(risk=0, warnings=8))
    assert decision.action == ALLOW


def test_trusted_user_always_allowed():
    decision = apply_policy(context(risk=4, trusted=True))
    assert decision.action == ALLOW
    assert decision.rule == "trusted_user"


def test_override_action_wins_over_everything():
    decision = apply_policy(
        context(risk=4, trusted=False, override_action=BLOCK)
    )
    assert decision.action == BLOCK
    assert decision.rule == "per_user_override"


def test_block_disabled_by_default_even_at_high_risk():
    decision = apply_policy(context(risk=5))
    assert decision.action == HIGH_RISK
    assert decision.rule == "high_risk"


def test_block_enabled_and_high_risk_yields_block():
    chat = ChatConfig(chat_id="test-chat", block_enabled=True)
    decision = apply_policy(context(risk=5, chat=chat))
    assert decision.action == BLOCK
    assert decision.rule == "block_high_risk"


def test_block_enabled_but_below_threshold_not_blocked():
    chat = ChatConfig(chat_id="test-chat", block_enabled=True)
    decision = apply_policy(context(risk=4, chat=chat))
    assert decision.action == HIGH_RISK


def test_lenient_sensitivity_raises_review_threshold():
    chat = ChatConfig(chat_id="test-chat", sensitivity=SENSITIVITY_LENIENT)
    decision = apply_policy(context(risk=2, chat=chat))
    assert decision.action == ALLOW


def test_lenient_sensitivity_review_at_three():
    chat = ChatConfig(chat_id="test-chat", sensitivity=SENSITIVITY_LENIENT)
    decision = apply_policy(context(risk=3, chat=chat))
    assert decision.action == REVIEW


def test_lenient_sensitivity_still_high_risk_at_five():
    chat = ChatConfig(chat_id="test-chat", sensitivity=SENSITIVITY_LENIENT)
    decision = apply_policy(context(risk=5, chat=chat))
    assert decision.action == HIGH_RISK


def test_strict_sensitivity_high_risk_at_three():
    chat = ChatConfig(chat_id="test-chat", sensitivity=SENSITIVITY_STRICT)
    decision = apply_policy(context(risk=3, chat=chat))
    assert decision.action == HIGH_RISK


def test_chat_threshold_override_used_instead_of_preset():
    chat = ChatConfig(
        chat_id="test-chat",
        sensitivity=SENSITIVITY_LENIENT,
        high_risk_min_risk=2,
        review_min_risk=1,
    )
    decision = apply_policy(context(risk=2, chat=chat))
    assert decision.action == HIGH_RISK


def test_default_chat_config_uses_standard_presets():
    chat = ChatConfig(chat_id="test-chat")
    assert chat.sensitivity == SENSITIVITY_STANDARD
    assert chat.effective_high_risk_min == 4
    assert chat.effective_review_min == 2
    assert chat.effective_escalate_violations == 5
    assert chat.block_enabled is False


def test_chat_config_persists_and_round_trips():
    config = ChatConfig(
        chat_id="chat-42",
        sensitivity=SENSITIVITY_STRICT,
        high_risk_min_risk=2,
        escalate_min_violations=3,
        block_enabled=True,
    )
    save_chat_config(config)

    loaded = get_chat_config("chat-42")
    assert loaded.sensitivity == SENSITIVITY_STRICT
    assert loaded.high_risk_min_risk == 2
    assert loaded.escalate_min_violations == 3
    assert loaded.block_enabled is True


def test_chat_config_update_overwrites_values():
    save_chat_config(
        ChatConfig(chat_id="chat-7", block_enabled=True)
    )
    save_chat_config(
        ChatConfig(chat_id="chat-7", sensitivity=SENSITIVITY_LENIENT)
    )

    loaded = get_chat_config("chat-7")
    assert loaded.block_enabled is False
    assert loaded.sensitivity == SENSITIVITY_LENIENT


def test_missing_chat_config_returns_defaults():
    loaded = get_chat_config("never-saved")
    assert loaded.sensitivity == SENSITIVITY_STANDARD
    assert loaded.high_risk_min_risk is None


def test_user_trusted_persists():
    set_user_trusted("sender-99", True)
    user = get_user("sender-99")
    assert user is not None
    assert user[6] == 1


def test_user_override_persists():
    set_user_override("sender-99", BLOCK)
    user = get_user("sender-99")
    assert user[7] == BLOCK
    set_user_override("sender-99", None)
    assert get_user("sender-99")[7] is None


def test_handle_message_clean_message_allowed():
    result = handle_message(
        sender="msg-a",
        text="Hello everyone",
        chat_id="chat-a",
    )
    assert result["action"] == ALLOW
    assert result["warning"] == ""
    assert result["policy"]["rule"] == "allow"


def test_handle_message_high_risk_flagged():
    from database.database import add_approved_member

    add_approved_member("msg-b")
    result = handle_message(
        sender="msg-b",
        text="Transfer immediately http://192.168.1.1/pay",
        chat_id="chat-b",
    )
    assert result["action"] in {HIGH_RISK, REVIEW, DELETE}
    assert result["policy"]["chat_id"] == "chat-b"


def test_handle_message_escalates_repeat_offender():
    sender = "serial-offender"
    for _ in range(5):
        handle_message(
            sender=sender,
            text="Claim your prize money now",
            chat_id="chat-c",
        )

    result = handle_message(
        sender=sender,
        text="Claim your prize money again",
        chat_id="chat-c",
    )
    assert result["action"] in {ESCALATE, HIGH_RISK, WARN}
    assert result["warning"]


def test_handle_message_respects_chat_block_enabled_config():
    from database.database import add_approved_member

    add_approved_member("msg-e")
    save_chat_config(
        ChatConfig(chat_id="chat-d", block_enabled=True)
    )
    result = handle_message(
        sender="msg-e",
        text="URGENT send money now http://192.168.1.1/login",
        chat_id="chat-d",
    )
    assert result["policy"]["chat_id"] == "chat-d"
    assert result["action"] in {BLOCK, HIGH_RISK}


def test_warning_message_actions_have_text_or_empty():
    assert warning_message(ALLOW, []) == ""
    assert warning_message(BLOCK, ["x"]) == ""
    assert warning_message(WARN, ["x"]) != ""
    assert warning_message(REVIEW, ["x"]) != ""
    assert warning_message(ESCALATE, ["x"]) != ""
    assert warning_message(HIGH_RISK, ["x"]) != ""