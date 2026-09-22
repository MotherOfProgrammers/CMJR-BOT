from database.database import get_trusted_domains, is_approved_member
from policy.models import (
    ALLOW,
    BLOCK,
    DELETE,
    ESCALATE,
    HIGH_RISK,
    KICK,
    LOG,
    REVIEW,
    WARN,
    ChatConfig,
    PolicyContext,
    risk_label,
)
from policy.policy import apply_policy


LINK_POLICY_ALLOW_ALL = "ALLOW_ALL"
LINK_POLICY_REVIEW_UNKNOWN = "REVIEW_UNKNOWN"
LINK_POLICY_BLOCK_SUSPICIOUS = "BLOCK_SUSPICIOUS"
LINK_POLICY_BLOCK_ALL_EXTERNAL = "BLOCK_ALL_EXTERNAL"
LINK_POLICY_ALLOW_TRUSTED_ONLY = "ALLOW_TRUSTED_ONLY"

SEVERITY = {
    ALLOW: 0,
    LOG: 1,
    REVIEW: 2,
    WARN: 3,
    HIGH_RISK: 4,
    BLOCK: 5,
    ESCALATE: 6,
    DELETE: 7,
    KICK: 8,
}


def _escalate(action: str, candidate: str) -> str:
    return candidate if SEVERITY.get(candidate, 0) > SEVERITY.get(action, 0) else action


def _combined_link_class(links: list[dict]) -> tuple[str, list[dict]]:
    if not links:
        return "", []

    order = {"SAFE": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "DANGEROUS": 3, "ADULT": 4}
    worst = None
    suspicious_links = []

    for link in links:
        classification = str(link.get("classification") or "UNKNOWN").upper()

        if worst is None or order.get(classification, 1) > order.get(worst, 1):
            worst = classification

        if classification in ("SUSPICIOUS", "DANGEROUS", "ADULT"):
            suspicious_links.append(link)

    return worst or "UNKNOWN", suspicious_links


def _categories_from_analysis(analysis: dict, toxicity: dict, behavior: dict, links: list[dict]) -> list[str]:
    categories = []

    for flag in ("scam",):
        if flag in analysis and analysis[flag].get("risk", 0) > 0:
            categories.append("SCAM")

    if analysis.get("spam", {}).get("risk", 0) > 0:
        categories.append("SPAM")

    for category in toxicity.get("categories", []):
        if category not in categories:
            categories.append(category)

    for category in behavior.get("categories", []):
        if category not in categories:
            categories.append(category)

    for link in links:
        classification = str(link.get("classification") or "UNKNOWN").upper()

        if classification == "DANGEROUS" and "PHISHING" not in categories:
            categories.append("PHISHING")

        if classification == "ADULT" and "ADULT" not in categories:
            categories.append("ADULT")

    return categories


def evaluate_message(
    analysis: dict,
    toxicity: dict | None,
    behavior: dict | None,
    ai: dict | None,
    chat_config: ChatConfig,
    sender: str,
    chat_id: str,
    trusted: bool = False,
    role: str = "USER",
    can_send_links: bool = False,
    exempt_toxicity: bool = False,
    exempt_spam: bool = False,
    override_action: str | None = None,
) -> dict:
    toxicity = toxicity or {"risk": 0, "reasons": [], "categories": []}
    behavior = behavior or {"risk": 0, "reasons": [], "categories": [], "warning_count": 0}
    links = analysis.get("links", []) or []

    risk = analysis.get("risk", 0)

    if not exempt_toxicity:
        risk += toxicity["risk"]

    risk += behavior["risk"]

    risk = min(max(risk, 0), 10)

    combined_link_class, suspicious_links = _combined_link_class(links)

    base_decision = apply_policy(
        PolicyContext(
            risk=risk,
            sender=sender,
            chat_id=chat_id,
            warning_count=behavior.get("warning_count", 0),
            trusted=trusted,
            override_action=override_action,
            chat=chat_config,
        )
    )

    action = base_decision.action
    base_action = action
    reason = base_decision.rule
    link_verdict = None

    approved = is_approved_member(sender)
    link_allowed_for_sender = approved or trusted or can_send_links

    if links and not trusted and not can_send_links:
        policy = chat_config.effective_link_policy
        link_verdict = {
            "policy": policy,
            "count": len(links),
            "worst_class": combined_link_class,
        }

        candidate = None
        candidate_rule = None

        if policy == LINK_POLICY_ALLOW_ALL:
            pass

        elif policy == LINK_POLICY_REVIEW_UNKNOWN:
            if combined_link_class in ("SUSPICIOUS", "DANGEROUS"):
                candidate, candidate_rule = REVIEW, "link_review_unknown"
            elif combined_link_class in ("UNKNOWN",) and action == ALLOW:
                candidate, candidate_rule = LOG, "link_log_unknown"

        elif policy == LINK_POLICY_BLOCK_SUSPICIOUS:
            if combined_link_class in ("SUSPICIOUS", "DANGEROUS"):
                candidate, candidate_rule = BLOCK, "link_block_suspicious"

        elif policy == LINK_POLICY_BLOCK_ALL_EXTERNAL:
            if combined_link_class not in ("SAFE", ""):
                candidate, candidate_rule = BLOCK, "link_block_external"

        elif policy == LINK_POLICY_ALLOW_TRUSTED_ONLY:
            trusted_domains = {d.lower() for d in get_trusted_domains()}

            safe = True

            for link in links:
                if link.get("domain", "").lower() not in trusted_domains:
                    safe = False
                    break

            if not safe:
                candidate, candidate_rule = BLOCK, "link_allow_trusted_only"

        if candidate is not None:
            action = _escalate(action, candidate)

            if action == candidate:
                reason = candidate_rule

    if links and not link_allowed_for_sender:
        action = DELETE
        reason = "link_sender_not_approved"

    if any(
        str(link.get("classification") or "").upper() == "ADULT"
        for link in links
    ):
        action = DELETE
        reason = "adult_content_link"

    if toxicity["categories"]:
        if "THREAT" in toxicity["categories"]:
            action = DELETE
            reason = "threat_detected"
        elif "HARASSMENT" in toxicity["categories"]:
            action = DELETE
            reason = "harassment_detected"
        elif "TOXIC" in toxicity["categories"]:
            action = DELETE
            reason = "toxicity_detected"

    if ai and "THREAT" in ai.get("categories", []) and ai.get("confidence", 0) >= 0.7:
        if action == ALLOW:
            action = REVIEW
            reason = "ai_threat_advisory"

    ai_categories = ai.get("categories", []) if ai else []

    if (
        ai
        and ai.get("confidence", 0) >= 0.8
        and ai.get("toxicity", 0) >= 0.6
        and any(category in ai_categories for category in ("TOXIC", "HARASSMENT", "ADULT"))
    ):
        action = DELETE
        reason = (
            "ai_adult_advisory"
            if "ADULT" in ai_categories
            else "ai_toxicity_advisory"
        )

    categories = _categories_from_analysis(analysis, toxicity, behavior, links)

    should_warn = chat_config.effective_auto_warn and action in (
        WARN,
        REVIEW,
        HIGH_RISK,
        ESCALATE,
        BLOCK,
    )
    should_delete = (
        chat_config.effective_auto_delete
        and action in (DELETE, HIGH_RISK, ESCALATE, BLOCK)
    )
    should_block = chat_config.effective_auto_block and action == BLOCK
    should_kick = chat_config.effective_auto_kick and action in (BLOCK, KICK)

    return {
        "action": action,
        "rule": reason,
        "risk": risk,
        "risk_label": risk_label(risk),
        "categories": categories,
        "reasons": (
            toxicity.get("reasons", [])
            + analysis.get("spam", {}).get("reasons", [])
            + analysis.get("scam", {}).get("reasons", [])
            + behavior.get("reasons", [])
        ),
        "link_verdict": link_verdict,
        "suspicious_links": suspicious_links,
        "ai_used": ai is not None,
        "ai_advisory": ai,
        "should_warn": should_warn,
        "should_delete": should_delete,
        "should_block": should_block,
        "should_kick": should_kick,
        "base_action": base_action,
        "base_rule": base_decision.rule,
    }


def can_enforce_delete(role: str, permissions: set[str]) -> bool:
    return "ALLOW_DELETE" in permissions or role in ("OWNER", "ADMIN")