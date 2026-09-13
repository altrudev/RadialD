from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class WeakLinkStatus(str, Enum):
    DETECTED = "DETECTED"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"
    UNRESOLVED = "UNRESOLVED"


class SafeAutonomy(str, Enum):
    HUMAN_REQUIRED = "human_required"
    CONDITIONAL_EXECUTION = "conditional_execution"
    BOUNDED_AUTONOMY = "bounded_autonomy"
    AUTONOMOUS_WITH_RECEIPTS = "autonomous_with_receipts"


@dataclass(frozen=True)
class WeakLinkSignal:
    name: str
    severity: float
    confidence: float
    status: WeakLinkStatus = WeakLinkStatus.DETECTED
    affects: tuple[str, ...] = ()
    propagation_depth: int = 0
    reversible: bool = True
    evidence: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("weak-link name must not be empty")
        if not 0.0 <= self.severity <= 1.0:
            raise ValueError("severity must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.propagation_depth < 0:
            raise ValueError("propagation_depth must be non-negative")

    @property
    def residual_risk(self) -> float:
        multiplier = {
            WeakLinkStatus.CLOSED: 0.0,
            WeakLinkStatus.CONTAINED: 0.35,
            WeakLinkStatus.DETECTED: 0.75,
            WeakLinkStatus.UNRESOLVED: 1.0,
        }[self.status]
        return min(1.0, self.severity * self.confidence * multiplier)


@dataclass(frozen=True)
class WeakLinkPolicy:
    human_required_at: float = 0.80
    conditional_at: float = 0.50
    bounded_at: float = 0.20

    def __post_init__(self) -> None:
        values = (self.human_required_at, self.conditional_at, self.bounded_at)
        if any(not 0.0 <= value <= 1.0 for value in values):
            raise ValueError("policy thresholds must be between 0 and 1")
        if not self.human_required_at >= self.conditional_at >= self.bounded_at:
            raise ValueError("policy thresholds must be descending")


@dataclass(frozen=True)
class WeakLinkReport:
    system_assurance: float
    bounding_link: WeakLinkSignal | None
    maximum_safe_autonomy: SafeAutonomy
    links: tuple[WeakLinkSignal, ...]


class WeakLinkAnalyzer:
    """Rank explicit assurance signals and identify the current bounding link."""

    def __init__(self, policy: WeakLinkPolicy | None = None) -> None:
        self.policy = policy or WeakLinkPolicy()

    def analyze(self, signals: Iterable[WeakLinkSignal]) -> WeakLinkReport:
        links = tuple(signals)
        ranked = sorted(
            links,
            key=lambda link: (
                link.residual_risk,
                not link.reversible,
                link.propagation_depth,
                link.name,
            ),
            reverse=True,
        )
        bounding = ranked[0] if ranked and ranked[0].residual_risk > 0 else None
        max_risk = bounding.residual_risk if bounding is not None else 0.0
        assurance = max(0.0, min(1.0, 1.0 - max_risk))

        if max_risk >= self.policy.human_required_at:
            autonomy = SafeAutonomy.HUMAN_REQUIRED
        elif max_risk >= self.policy.conditional_at:
            autonomy = SafeAutonomy.CONDITIONAL_EXECUTION
        elif max_risk >= self.policy.bounded_at:
            autonomy = SafeAutonomy.BOUNDED_AUTONOMY
        else:
            autonomy = SafeAutonomy.AUTONOMOUS_WITH_RECEIPTS

        return WeakLinkReport(
            system_assurance=assurance,
            bounding_link=bounding,
            maximum_safe_autonomy=autonomy,
            links=links,
        )
