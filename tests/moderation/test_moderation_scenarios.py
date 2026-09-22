import pytest

from actions.replies import handle_message
from database.database import add_approved_member, add_trusted_domain
from policy.models import (
    ALLOW,
    BLOCK,
    DELETE,
    ESCALATE,
    HIGH_RISK,
    LOG,
    REVIEW,
    WARN,
)


REPEAT_OFFENDER_TEXT = "Claim your prize http://bit.ly/off"


def test_normal_message_allowed():
    result = handle_message(sender="n1", text="Hi everyone!", chat_id="g1")
    assert result["action"] == ALLOW
    assert result["risk"] == 0


def test_suspicious_link_deleted_for_unapproved():
    result = handle_message(sender="n2", text="Check http://bit.ly/xyz", chat_id="g1")
    assert result["action"] == DELETE
    assert result["policy"]["link_verdict"]["worst_class"] == "SUSPICIOUS"


def test_phishing_link_deleted_for_unapproved():
    result = handle_message(
        sender="n3",
        text="Login now http://192.168.1.1/login",
        chat_id="g1",
    )
    assert result["action"] == DELETE
    assert "PHISHING" in result["categories"]


def test_shortened_url_still_classified_for_approved():
    add_approved_member("approved-short")
    result = handle_message(sender="approved-short", text="Deal at http://t.co/abc", chat_id="g1")
    assert result["risk"] >= 1
    assert result["policy"]["link_verdict"]["worst_class"] == "SUSPICIOUS"
    assert result["action"] in {ALLOW, LOG, REVIEW}


def test_toxic_message_deleted():
    result = handle_message(sender="n5", text="You are pathetic", chat_id="g1")
    assert result["action"] == DELETE
    assert "TOXIC" in result["categories"]


def test_harassment_message_deleted():
    result = handle_message(sender="n6", text="Your mother should be ashamed", chat_id="g1")
    assert result["action"] == DELETE
    assert "HARASSMENT" in result["categories"]


def test_threat_message_deleted():
    result = handle_message(sender="n7", text="I will kill you", chat_id="g1")
    assert result["action"] == DELETE
    assert "THREAT" in result["categories"]


def test_profanity_deleted():
    result = handle_message(sender="swear-1", text="This is complete bullshit", chat_id="g1")
    assert result["action"] == DELETE
    assert "TOXIC" in result["categories"]


def test_common_words_not_flagged_as_profanity():
    result = handle_message(sender="ok-1", text="Hello everyone, how are you", chat_id="g1")
    assert result["action"] == ALLOW


def test_adult_domain_link_deleted():
    result = handle_message(sender="adult-1", text="Check out https://www.xvideos.com/video123", chat_id="g1")
    assert result["action"] == DELETE
    assert result["categories"] == ["ADULT"]


def test_adult_keyword_link_deleted():
    result = handle_message(sender="adult-2", text="See this https://example-xx.com/nsfw-clips", chat_id="g1")
    assert result["action"] == DELETE
    assert "ADULT" in result["categories"]


def test_adult_rta_label_deleted():
    result = handle_message(sender="adult-3", text="Free clips https://funnypromo.net/watch?rta-8067=1", chat_id="g1")
    assert result["action"] == DELETE
    assert "ADULT" in result["categories"]


def test_clean_express_domain_not_adult():
    from database.database import add_approved_member

    add_approved_member("ok-2")

    result = handle_message(sender="ok-2", text="Deploy with https://expressjs.com", chat_id="g1")
    assert "ADULT" not in result["categories"]
    assert result["action"] in {ALLOW, LOG, REVIEW}


@pytest.mark.parametrize(
    "profane_text",
    [
        "ඔයා මෝඩයෙක්",
        "මට බූරුවෙක් වගේ",
        "ඕකා කෙළවෙනොයි",
        "kelevano",
        "muda thamba ekek",
        "இதோ முட்டாள்",
        "neeyum punda da",
        "eres un imbécil",
        "eres un malparido",
        "أنت غبي",
        "انت شرموطة",
        "तुम गधे हो",
        "tum chutiya ho",
        "bhenchod kya kar raha",
        "putain de merde",
        "wewe ni mjinga",
        "bodoh sekali",
        "dasar jembut",
        "thằng ngu",
    ],
)
def test_multilingual_profanity_deleted(profane_text):
    result = handle_message(sender="ml-1", text=profane_text, chat_id="g1")
    assert result["action"] == DELETE
    assert result["categories"] == ["TOXIC"]


@pytest.mark.parametrize(
    "clean_text",
    [
        "Hello everyone, how are you",
        "නන්ද කියන්න",
        "நான் நன்றாக இருக்கிறேன்",
        "Estoy feliz hoy",
        "आप सब अच्छे हैं",
        "Asante sana",
    ],
)
def test_multilingual_clean_not_flagged(clean_text):
    result = handle_message(sender="ml-2", text=clean_text, chat_id="g1")
    assert result["action"] in {ALLOW, LOG, REVIEW}
    assert "TOXIC" not in result["categories"]


@pytest.mark.parametrize(
    "adult_link",
    [
        "Watch now https://hanime.tv/watch/123",
        "Látnivaló https://example-hello.shop/hentai/456",
        "Check https://example.com/clips?ecchi=1",
        "看片 https://example-site.net/色情",
    ],
)
def test_international_adult_link_deleted(adult_link):
    result = handle_message(sender="ml-3", text=adult_link, chat_id="g1")
    assert result["action"] == DELETE
    assert "ADULT" in result["categories"]


def test_spam_burst_flood():
    for _ in range(6):
        handle_message(sender="spammer", text=f"msg {_}", chat_id="g2")
    result = handle_message(sender="spammer", text="burst end", chat_id="g2")
    assert result["risk"] >= 2
    assert "SPAM" in result["categories"]


def test_repeated_message_similarity():
    handle_message(sender="repeater", text="Buy this thing now", chat_id="g3")
    result = handle_message(sender="repeater", text="Buy this thing now", chat_id="g3")
    assert result["risk"] >= 2
    assert "SPAM" in result["categories"]


def test_trusted_domain_allowed_for_approved_member():
    add_approved_member("approved-4")
    add_trusted_domain("bit.ly")
    result = handle_message(sender="approved-4", text="http://bit.ly/abc", chat_id="g4")
    assert result["action"] == ALLOW


def test_approved_member_unknown_url_stays_unknown():
    add_approved_member("approved-u1")
    result = handle_message(sender="approved-u1", text="See http://totally-fine-site.com/p", chat_id="g5")
    verdict = result["policy"]["link_verdict"]
    assert verdict["worst_class"] == "UNKNOWN"
    assert result["action"] in {ALLOW, LOG}


def test_unapproved_unknown_url_deleted():
    result = handle_message(sender="u2", text="See http://totally-fine-site.com/p", chat_id="g5")
    assert result["action"] == DELETE


def test_group_message_processed():
    result = handle_message(sender="gm1", text="Hello group", chat_id="123@g.us")
    assert result["chat_id"] == "123@g.us"
    assert result["action"] == ALLOW


def test_private_message_processed():
    result = handle_message(sender="pm1", text="Hello private", chat_id="555")
    assert result["chat_id"] == "555"
    assert result["action"] == ALLOW


def test_serial_offender_repeated_links_deleted():
    for _ in range(5):
        handle_message(sender="serial", text=REPEAT_OFFENDER_TEXT, chat_id="g6")
    result = handle_message(sender="serial", text=REPEAT_OFFENDER_TEXT, chat_id="g6")
    assert result["action"] == DELETE


def test_user_override_block_enforced():
    from database.database import set_user_override

    set_user_override("banned-9", BLOCK)
    result = handle_message(sender="banned-9", text="Hello", chat_id="g7")
    assert result["action"] == BLOCK