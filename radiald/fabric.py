from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import islice
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

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


def _validate_names(values: tuple[str, ...], label: str) -> None:
    if len(values) > 64:
        raise ValueError(f"{label} exceeds 64 entries")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains duplicates")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} must contain non-empty strings")


@dataclass(frozen=True)
class EvidenceEnvelope:
    source: str
    source_schema: str
    artifact_digest: str
    verifier_id: str
    trust_anchor_fingerprint: str
    verified_at: str
    freshness_scope: str
    disposition: str
    bindings: Mapping[str, str]
    attestation_digest: str

    def __post_init__(self) -> None:
        if not self.source.strip() or len(self.source) > 128:
            raise ValueError("source required and must be <=128 chars")
        if not self.source_schema.strip() or len(self.source_schema) > 256:
            raise ValueError("source_schema required and must be <=256 chars")
        if not _sha256_text(self.artifact_digest):
            raise ValueError("artifact_digest must be sha256")
        if not self.verifier_id.strip() or len(self.verifier_id) > 256:
            raise ValueError("verifier_id required and must be <=256 chars")
        if not _sha256_text(self.trust_anchor_fingerprint):
            raise ValueError("trust_anchor_fingerprint must be sha256")
        _utc(self.verified_at)
        if self.freshness_scope not in ALLOWED_SCOPES:
            raise ValueError("unsupported freshness_scope")
        if self.disposition not in ALLOWED_DISPOSITIONS:
            raise ValueError("unsupported disposition")
        if not _sha256_text(self.attestation_digest):
            raise ValueError("attestation_digest must be sha256")

        copied = dict(self.bindings)
        if len(copied) > 64:
            raise ValueError("too many bindings")
        for key, value in copied.items():
            if not isinstance(key, str) or not key.strip() or len(key) > 128:
                raise ValueError("binding names must be non-empty strings <=128 chars")
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError("binding values must be non-empty strings <=4096 chars")
        object.__setattr__(self, "bindings", MappingProxyType(copied))

    def fingerprint(self) -> str:
        return stable_digest({
            "source": self.source,
            "source_schema": self.source_schema,
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
    preflight_sources: tuple[str, ...] = ()
    max_envelopes: int = 64

    def __post_init__(self) -> None:
        if not self.policy_id.strip() or len(self.policy_id) > 256:
            raise ValueError("policy_id required and must be <=256 chars")
        if not self.action_class.strip() or len(self.action_class) > 128:
            raise ValueError("action_class required and must be <=128 chars")
        _validate_names(self.required_sources, "required_sources")
        _validate_names(self.required_binding_fields, "required_binding_fields")
        _validate_names(self.preflight_sources, "preflight_sources")
        if self.preflight_sources and not set(self.preflight_sources).issubset(
            self.required_sources
        ):
            raise ValueError("preflight_sources must be a subset of required_sources")
        if self.require_preflight and not (
            self.preflight_sources or self.required_sources
        ):
            raise ValueError("preflight requires at least one declared source")
        if self.max_preflight_age_seconds < 0:
            raise ValueError("max_preflight_age_seconds must be non-negative")
        if self.max_envelopes < 1 or self.max_envelopes > 1024:
            raise ValueError("max_envelopes must be between 1 and 1024")


@dataclass(frozen=True)
class BindingReport:
    consistent: bool
    resolved: Mapping[str, str]
    conflicts: Mapping[str, tuple[str, ...]]
    missing: tuple[str, ...]
    budget_exceeded: bool = False


@dataclass(frozen=True)
class AssuranceFabricResult:
    report: WeakLinkReport
    binding: BindingReport
    envelope_fingerprints: tuple[str, ...]
    policy_digest: str


def _collect_bounded(
    envelopes: Iterable[EvidenceEnvelope],
    limit: int,
) -> tuple[tuple[EvidenceEnvelope, ...], bool]:
    sample = tuple(islice(iter(envelopes), limit + 1))
    return sample[:limit], len(sample) > limit


def _evaluate_trust(
    items: tuple[EvidenceEnvelope, ...],
    verifier: Callable[[EvidenceEnvelope], bool],
) -> dict[str, bool]:
    trust: dict[str, bool] = {}
    for envelope in items:
        fingerprint = envelope.fingerprint()
        if fingerprint in trust:
            continue
        if envelope.disposition != "VERIFIED":
            trust[fingerprint] = False
            continue
        try:
            trust[fingerprint] = bool(verifier(envelope))
        except Exception:
            trust[fingerprint] = False
    return trust


def _trusted(envelope: EvidenceEnvelope, trust: Mapping[str, bool]) -> bool:
    return bool(trust.get(envelope.fingerprint(), False))


def _bind_trusted(
    items: tuple[EvidenceEnvelope, ...],
    trust: Mapping[str, bool],
    *,
    required_fields: Iterable[str],
    budget_exceeded: bool,
) -> BindingReport:
    resolved: dict[str, str] = {}
    conflicts: dict[str, tuple[str, ...]] = {}
    missing: list[str] = []

    for field in tuple(required_fields):
        values = sorted({
            envelope.bindings[field]
            for envelope in items
            if _trusted(envelope, trust) and field in envelope.bindings
        })
        if not values:
            missing.append(field)
        elif len(values) == 1:
            resolved[field] = values[0]
        else:
            conflicts[field] = tuple(values)

    return BindingReport(
        consistent=not conflicts and not missing and not budget_exceeded,
        resolved=MappingProxyType(resolved),
        conflicts=MappingProxyType(conflicts),
        missing=tuple(sorted(missing)),
        budget_exceeded=budget_exceeded,
    )


def bind_evidence(
    envelopes: Iterable[EvidenceEnvelope],
    *,
    verifier: Callable[[EvidenceEnvelope], bool],
    required_fields: Iterable[str] = DEFAULT_BINDING_FIELDS,
    max_envelopes: int = 64,
) -> BindingReport:
    if max_envelopes < 1 or max_envelopes > 1024:
        raise ValueError("max_envelopes must be between 1 and 1024")
    fields = tuple(required_fields)
    _validate_names(fields, "required_fields")
    items, exceeded = _collect_bounded(envelopes, max_envelopes)
    trust = _evaluate_trust(items, verifier)
    return _bind_trusted(
        items,
        trust,
        required_fields=fields,
        budget_exceeded=exceeded,
    )


def _policy_signals_from_items(
    items: tuple[EvidenceEnvelope, ...],
    *,
    budget_exceeded: bool,
    trust: Mapping[str, bool],
    policy: EvidencePolicy,
    now: str,
) -> tuple[WeakLinkSignal, ...]:
    current = _utc(now)
    signals: list[WeakLinkSignal] = []
    by_source: dict[str, list[EvidenceEnvelope]] = {}

    if budget_exceeded:
        signals.append(WeakLinkSignal(
            name="evidence_budget",
            severity=1.0,
            confidence=1.0,
            status=WeakLinkStatus.UNRESOLVED,
            affects=("provenance", "execution"),
            propagation_depth=4,
            reversible=False,
            evidence=f"envelope count exceeds {policy.max_envelopes}",
        ))

    for envelope in items:
        by_source.setdefault(envelope.source, []).append(envelope)

    for source in policy.required_sources:
        matches = by_source.get(source, [])
        closed = any(_trusted(envelope, trust) for envelope in matches)
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

    fresh_sources = policy.preflight_sources
    if policy.require_preflight and not fresh_sources:
        fresh_sources = policy.required_sources

    for source in fresh_sources:
        candidates = [
            envelope for envelope in by_source.get(source, [])
            if _trusted(envelope, trust)
            and envelope.freshness_scope == "preflight"
        ]
        if not candidates:
            status = WeakLinkStatus.UNRESOLVED
            evidence = "trusted preflight evidence missing"
        else:
            ages = [
                (current - _utc(envelope.verified_at)).total_seconds()
                for envelope in candidates
            ]
            if any(age < 0 for age in ages):
                status = WeakLinkStatus.UNRESOLVED
                evidence = "preflight evidence timestamp is in the future"
            elif min(ages) > policy.max_preflight_age_seconds:
                status = WeakLinkStatus.UNRESOLVED
                evidence = "preflight evidence exceeds maximum age"
            else:
                status = WeakLinkStatus.CLOSED
                evidence = "preflight evidence within policy age"
        signals.append(WeakLinkSignal(
            name=f"evidence_freshness:{source}",
            severity=1.0,
            confidence=1.0,
            status=status,
            affects=("authority", "state", "execution"),
            propagation_depth=3,
            reversible=False,
            evidence=evidence,
        ))

    binding = _bind_trusted(
        items,
        trust,
        required_fields=policy.required_binding_fields,
        budget_exceeded=budget_exceeded,
    )
    if binding.budget_exceeded:
        binding_status = WeakLinkStatus.UNRESOLVED
        binding_evidence = "evidence budget exceeded"
    elif binding.conflicts:
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


def policy_signals(
    envelopes: Iterable[EvidenceEnvelope],
    policy: EvidencePolicy,
    *,
    now: str,
    verifier: Callable[[EvidenceEnvelope], bool],
) -> tuple[WeakLinkSignal, ...]:
    items, exceeded = _collect_bounded(envelopes, policy.max_envelopes)
    trust = _evaluate_trust(items, verifier)
    return _policy_signals_from_items(
        items,
        budget_exceeded=exceeded,
        trust=trust,
        policy=policy,
        now=now,
    )


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
    verifier: Callable[[EvidenceEnvelope], bool],
    analyzer: WeakLinkAnalyzer | None = None,
) -> AssuranceFabricResult:
    items, exceeded = _collect_bounded(envelopes, policy.max_envelopes)
    trust = _evaluate_trust(items, verifier)
    producer_items = tuple(producer_signals)
    policy_items = _policy_signals_from_items(
        items,
        budget_exceeded=exceeded,
        trust=trust,
        policy=policy,
        now=now,
    )
    contradiction_items = contradiction_signals(producer_items + policy_items)
    report = (analyzer or WeakLinkAnalyzer()).analyze(
        producer_items + policy_items + contradiction_items
    )
    binding = _bind_trusted(
        items,
        trust,
        required_fields=policy.required_binding_fields,
        budget_exceeded=exceeded,
    )
    policy_digest = stable_digest({
        "policy_id": policy.policy_id,
        "action_class": policy.action_class,
        "required_sources": policy.required_sources,
        "required_binding_fields": policy.required_binding_fields,
        "max_preflight_age_seconds": policy.max_preflight_age_seconds,
        "require_preflight": policy.require_preflight,
        "preflight_sources": policy.preflight_sources,
        "max_envelopes": policy.max_envelopes,
    })
    return AssuranceFabricResult(
        report=report,
        binding=binding,
        envelope_fingerprints=tuple(
            sorted(envelope.fingerprint() for envelope in items)
        ),
        policy_digest=policy_digest,
    )
