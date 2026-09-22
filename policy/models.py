from dataclasses import dataclass

import config


ALLOW = "ALLOW"
LOG = "LOG"
WARN = "WARN"
REVIEW = "REVIEW"
BLOCK = "BLOCK"
ESCALATE = "ESCALATE"
HIGH_RISK = "HIGH_RISK"
DELETE = "DELETE"
KICK = "KICK"

ALL_ACTIONS = (
    ALLOW,
    LOG,
    WARN,
    REVIEW,
    BLOCK,
    ESCALATE,
    HIGH_RISK,
    DELETE,
    KICK,
)

RISK_LABELS = {
    0: "SAFE",
    1: "LOW",
    2: "LOW",
    3: "MEDIUM",
    4: "MEDIUM",
    5: "HIGH",
    6: "HIGH",
    7: "HIGH",
    8: "CRITICAL",
    9: "CRITICAL",
    10: "CRITICAL",
}

SENSITIVITY_LENIENT = "lenient"
SENSITIVITY_STANDARD = "standard"
SENSITIVITY_STRICT = "strict"

SENSITIVITY_PRESETS = {
    SENSITIVITY_LENIENT: {
        "high_risk_min_risk": 5,
        "review_min_risk": 3,
    },
    SENSITIVITY_STANDARD: {
        "high_risk_min_risk": 4,
        "review_min_risk": 2,
    },
    SENSITIVITY_STRICT: {
        "high_risk_min_risk": 3,
        "review_min_risk": 2,
    },
}


def risk_label(risk: int) -> str:
    return RISK_LABELS.get(min(max(risk, 0), 10), "UNKNOWN")


@dataclass
class ChatConfig:
    chat_id: str
    sensitivity: str = SENSITIVITY_STANDARD
    high_risk_min_risk: int | None = None
    review_min_risk: int | None = None
    escalate_min_violations: int | None = None
    block_enabled: bool = False
    enabled: bool | None = True
    ai_enabled: bool | None = True
    link_policy: str | None = None
    toxicity_enabled: bool | None = True
    spam_enabled: bool | None = True
    auto_delete: bool | None = None
    auto_warn: bool | None = None
    auto_block: bool | None = None
    auto_kick: bool | None = None

    @property
    def effective_high_risk_min(self) -> int:
        if self.high_risk_min_risk is not None:
            return self.high_risk_min_risk

        preset = SENSITIVITY_PRESETS.get(
            self.sensitivity,
            SENSITIVITY_PRESETS[SENSITIVITY_STANDARD],
        )
        return preset["high_risk_min_risk"]

    @property
    def effective_review_min(self) -> int:
        if self.review_min_risk is not None:
            return self.review_min_risk

        preset = SENSITIVITY_PRESETS.get(
            self.sensitivity,
            SENSITIVITY_PRESETS[SENSITIVITY_STANDARD],
        )
        return preset["review_min_risk"]

    @property
    def effective_escalate_violations(self) -> int:
        if self.escalate_min_violations is not None:
            return self.escalate_min_violations

        return 5

    @property
    def effective_enabled(self) -> bool:
        return True if self.enabled is None else self.enabled

    @property
    def effective_ai_enabled(self) -> bool:
        return True if self.ai_enabled is None else self.ai_enabled

    @property
    def effective_link_policy(self) -> str:
        if self.link_policy:
            return self.link_policy.upper()
        return config.DEFAULT_LINK_POLICY.upper()

    @property
    def effective_toxicity_enabled(self) -> bool:
        return True if self.toxicity_enabled is None else self.toxicity_enabled

    @property
    def effective_spam_enabled(self) -> bool:
        return True if self.spam_enabled is None else self.spam_enabled

    @property
    def effective_auto_delete(self) -> bool:
        if self.auto_delete is not None:
            return self.auto_delete
        return config.AUTO_DELETE

    @property
    def effective_auto_warn(self) -> bool:
        if self.auto_warn is not None:
            return self.auto_warn
        return config.AUTO_WARN

    @property
    def effective_auto_block(self) -> bool:
        if self.auto_block is not None:
            return self.auto_block
        return config.AUTO_BLOCK

    @property
    def effective_auto_kick(self) -> bool:
        if self.auto_kick is not None:
            return self.auto_kick
        return config.AUTO_KICK


@dataclass
class PolicyContext:
    risk: int
    sender: str
    chat_id: str
    warning_count: int = 0
    trusted: bool = False
    override_action: str | None = None
    chat: ChatConfig | None = None


@dataclass
class PolicyDecision:
    action: str
    rule: str | None = None