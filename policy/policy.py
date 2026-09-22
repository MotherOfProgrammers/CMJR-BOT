from policy.models import (
    ALLOW,
    BLOCK,
    ESCALATE,
    HIGH_RISK,
    REVIEW,
    WARN,
    ChatConfig,
    PolicyContext,
    PolicyDecision,
)


def apply_policy(context: PolicyContext) -> PolicyDecision:
    if context.override_action:
        return PolicyDecision(
            action=context.override_action,
            rule="per_user_override",
        )

    if context.trusted:
        return PolicyDecision(
            action=ALLOW,
            rule="trusted_user",
        )

    chat = context.chat or ChatConfig(chat_id=context.chat_id)

    risk = context.risk
    warnings = context.warning_count

    if risk > 0 and warnings >= chat.effective_escalate_violations:
        return PolicyDecision(
            action=ESCALATE,
            rule="escalate_serial",
        )

    if risk >= 3 and warnings >= 3:
        return PolicyDecision(
            action=ESCALATE,
            rule="escalate_high_serial",
        )

    if risk >= chat.effective_high_risk_min:
        if chat.block_enabled and risk >= 5:
            return PolicyDecision(
                action=BLOCK,
                rule="block_high_risk",
            )
        return PolicyDecision(
            action=HIGH_RISK,
            rule="high_risk",
        )

    if risk >= chat.effective_review_min:
        return PolicyDecision(
            action=REVIEW,
            rule="review",
        )

    if warnings >= 3 and risk > 0:
        return PolicyDecision(
            action=WARN,
            rule="warn_borderline",
        )

    return PolicyDecision(
        action=ALLOW,
        rule="allow",
    )