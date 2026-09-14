from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from .canonical import stable_digest
from .weaklink import WeakLinkAnalyzer, WeakLinkReport, WeakLinkSignal, WeakLinkStatus


ALLOWED_SCOPES = {"historical", "preflight"}
ALLOWED_DISPOSITIONS = {"VERIFIED", "FAILED", "INDETERMINATE"}
DEFAULT_BINDING_FIELDS = (
    "action_digest",
    "resource_id",
    "policy_digest",
    "revision",
    "predecessor_digest",
    "successor_digest",
    "execution_digest",
)


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone-aware timestamp required")
    return parsed.astimezone(timezone.utc)


def _sha256_text(value: str) -> bool:
    if not isinstance(value, str):
        return False
    text = value[7:] if value.startswith("sha256:") else value
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


@dataclass(frozen=True)
class EvidenceEnvelope:
    source: str
    artifact_digest: str
    verifier_id: str
    trust_anchor_fingerprint: str
    verified_at: str
    freshness_scope: str
    disposition: str
    bindings: Mapping[str, str]
    attestation_digest: str

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("source required")
        if not _sha256_text(self.artifact_digest):
            raise ValueError("artifact_digest must be sha256")
        if not self.verifier_id.strip():
            raise ValueError("verifier_id required")
        if not _sha256_text(self.trust_anchor_fingerprint):
            raise ValueError("trust_anchor_fingerprint must be sha256")
        _utc(self.verified_at)
        if self.freshness_scope not in ALLOWED_SCOPES:
            raise ValueError("unsupported freshness_scope")
        if self.disposition not in ALLOWED_DISPOSITIONS:
            raise ValueError("unsupported disposition")
        if not _sha256_text(self.attestation_digest):
            raise ValueError("attestation_digest must be sha256")
        for key, value in self.bindings.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("binding names must be non-empty strings")
            if not isinstance(value, str) or not value:
                raise ValueError("binding values must be non-empty strings")

    @property
    def trusted(self) -> bool:
        return self.disposition == "VERIFIED"

    def fingerprint(self) -> str:
        return stable_digest({
            "source": self.source,
            "artifact_digest": self.artifact_digest,
            "verifier_id": self.verifier_id,
            "trust_anchor_fingerprint": self.trust_anchor_fingerprint,
            "verified_at": self.verified_at,
            "freshness_scope": self.freshness_scope,
            "disposition": self.disposition,
            "bindings": dict(self.bindings),
            "attestation_digest": self.attestation_digest,
        })


@dataclass(frozen=True)
class EvidencePolicy:
    policy_id: str
    action_class: str
    required_sources: tuple[str, ...] = ()
    required_binding_fields: tuple[str, ...] = DEFAULT_BINDING_FIELDS
    max_preflight_age_seconds: int = 60
    require_preflight: bool = False

    def __post_init__(self) -> None:
        if not self.policy_id.strip():
            raise ValueError("policy_id required")
        if not self.action_class.strip():
            raise ValueError("action_class required")
        if self.max_preflight_age_seconds < 0:
            raise ValueError("max_preflight_age_seconds must be non-negative")


@dataclass(frozen=True)
class BindingReport:
    consistent: bool
    resolved: Mapping[str, str]
    conflicts: Mapping[str, tuple[str, ...]]
    missing: tuple[str, ...]


@dataclass(frozen=True)
class AssuranceFabricResult:
    report: WeakLinkReport
    binding: BindingReport
    envelope_fingerprints: tuple[str, ...]
    policy_digest: str


def bind_evidence(
    envelopes: Iterable[EvidenceEnvelope],
    *,
    required_fields: Iterable[str] = DEFAULT_BINDING_FIELDS,
) -> BindingReport:
    items = tuple(envelopes)
    resolved: dict[str, str] = {}
    conflicts: dict[str, tuple[str, ...]] = {}
    missing: list[str] = []

    for field in tuple(required_fields):
        values = sorted({
            envelope.bindings[field]
            for envelope in items
            if envelope.trusted and field in envelope.bindings
        })
        if not values:
            missing.append(field)
        elif len(values) == 1:
            resolved[field] = values[0]
        else:
            conflicts[field] = tuple(values)

    return BindingReport(
        consistent=not conflicts and not missing,
        resolved=resolved,
        conflicts=conflicts,
        missing=tuple(sorted(missing)),
    )


def policy_signals(
    envelopes: Iterable[EvidenceEnvelope],
    policy: EvidencePolicy,
    *,
    now: str,
) -> tuple[WeakLinkSignal, ...]:
    items = tuple(envelopes)
    current = _utc(now)
    signals: list[WeakLinkSignal] = []
    by_source: dict[str, list[EvidenceEnvelope]] = {}

    for envelope in items:
        by_source.setdefault(envelope.source, []).append(envelope)

    for source in policy.required_sources:
        matches = by_source.get(source, [])
        closed = any(envelope.trusted for envelope in matches)
        signals.append(WeakLinkSignal(
            name=f"required_evidence:{source}",
            severity=1.0,
            confidence=1.0,
            status=WeakLinkStatus.CLOSED if closed else WeakLinkStatus.UNRESOLVED,
            affects=("provenance", "execution"),
            propagation_depth=1,
            reversible=False,
            evidence=(
                "trusted verifier attestation present"
                if closed else "required trusted evidence missing"
            ),
        ))

    if policy.require_preflight:
        preflight = [
            envelope for envelope in items
            if envelope.trusted and envelope.freshness_scope == "preflight"
        ]
        if not preflight:
            status = WeakLinkStatus.UNRESOLVED
            evidence = "trusted preflight evidence missing"
        else:
            ages = [
                (current - _utc(envelope.verified_at)).total_seconds()
                for envelope in preflight
            ]
            if any(age < 0 for age in ages):
                status = WeakLinkStatus.UNRESOLVED
                evidence = "preflight evidence timestamp is in the future"
            elif max(ages) > policy.max_preflight_age_seconds:
                status = WeakLinkStatus.UNRESOLVED
                evidence = "preflight evidence exceeds maximum age"
            else:
                status = WeakLinkStatus.CLOSED
                evidence = "preflight evidence within policy age"
        signals.append(WeakLinkSignal(
            name="evidence_freshness",
            severity=1.0,
            confidence=1.0,
            status=status,
            affects=("authority", "state", "execution"),
            propagation_depth=3,
            reversible=False,
            evidence=evidence,
        ))

    binding = bind_evidence(items, required_fields=policy.required_binding_fields)
    if binding.conflicts:
        binding_status = WeakLinkStatus.UNRESOLVED
        binding_evidence = "conflicts=" + ",".join(sorted(binding.conflicts))
    elif binding.missing:
        binding_status = WeakLinkStatus.UNRESOLVED
        binding_evidence = "missing=" + ",".join(binding.missing)
    else:
        binding_status = WeakLinkStatus.CLOSED
        binding_evidence = "required bindings agree across trusted evidence"

    signals.append(WeakLinkSignal(
        name="cross_evidence_binding",
        severity=1.0,
        confidence=1.0,
        status=binding_status,
        affects=("authority", "state", "execution", "provenance"),
        propagation_depth=4,
        reversible=False,
        evidence=binding_evidence,
    ))
    return tuple(signals)


def contradiction_signals(
    signals: Iterable[WeakLinkSignal],
) -> tuple[WeakLinkSignal, ...]:
    grouped: dict[str, set[WeakLinkStatus]] = {}
    for signal in signals:
        grouped.setdefault(signal.name, set()).add(signal.status)

    contradictions: list[WeakLinkSignal] = []
    for name, statuses in sorted(grouped.items()):
        if WeakLinkStatus.CLOSED in statuses and len(statuses) > 1:
            contradictions.append(WeakLinkSignal(
                name=f"evidence_contradiction:{name}",
                severity=1.0,
                confidence=1.0,
                status=WeakLinkStatus.UNRESOLVED,
                affects=("provenance", "execution"),
                propagation_depth=4,
                reversible=False,
                evidence=(
                    "conflicting statuses="
                    + ",".join(sorted(status.value for status in statuses))
                ),
            ))
    return tuple(contradictions)


def analyze_assurance_fabric(
    *,
    envelopes: Iterable[EvidenceEnvelope],
    producer_signals: Iterable[WeakLinkSignal],
    policy: EvidencePolicy,
    now: str,
    analyzer: WeakLinkAnalyzer | None = None,
) -> AssuranceFabricResult:
    envelope_items = tuple(envelopes)
    producer_items = tuple(producer_signals)
    policy_items = policy_signals(envelope_items, policy, now=now)
    contradiction_items = contradiction_signals(producer_items + policy_items)
    all_signals = producer_items + policy_items + contradiction_items
    report = (analyzer or WeakLinkAnalyzer()).analyze(all_signals)
    binding = bind_evidence(
        envelope_items,
        required_fields=policy.required_binding_fields,
    )
    policy_digest = stable_digest({
        "policy_id": policy.policy_id,
        "action_class": policy.action_class,
        "required_sources": policy.required_sources,
        "required_binding_fields": policy.required_binding_fields,
        "max_preflight_age_seconds": policy.max_preflight_age_seconds,
        "require_preflight": policy.require_preflight,
    })
    return AssuranceFabricResult(
        report=report,
        binding=binding,
        envelope_fingerprints=tuple(
            sorted(envelope.fingerprint() for envelope in envelope_items)
        ),
        policy_digest=policy_digest,
    )
