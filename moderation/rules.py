from moderation.links import classify_url, find_links
from moderation.scam import detect_scam_signals
from moderation.spam import analyze_spam


def classify_domain(domain: str) -> str:
    result = classify_url(domain)

    return result["classification"]


def decide_action(risk: int) -> str:
    if risk >= 4:
        return "HIGH_RISK"

    if risk >= 2:
        return "REVIEW"

    return "ALLOW"


def analyze_message(
    sender: str,
    text: str,
    chat_id: str | None = None,
) -> dict:
    links = []

    for url in find_links(text):
        links.append(classify_url(url))

    scam = detect_scam_signals(text)

    spam = analyze_spam(
        sender=sender,
        message=text,
        links=find_links(text),
        chat_id=chat_id,
    )

    total_risk = scam["risk"]

    for link in links:
        total_risk += link["risk"]

    total_risk += spam["risk"]

    return {
        "risk": total_risk,
        "action": decide_action(total_risk),
        "scam": scam,
        "spam": spam,
        "links": links,
    }
