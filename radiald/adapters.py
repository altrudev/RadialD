from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .weaklink import WeakLinkAnalyzer, WeakLinkReport, WeakLinkSignal, WeakLinkStatus

_REQUIRED_RECEIPT_DIMENSIONS = (
    "semantic", "authority", "state", "resource", "security", "physical", "lineage"
)


def _signal(
    name: str,
    severity: float,
    confidence: float,
    status: WeakLinkStatus,
    *,
    affects: tuple[str, ...] = (),
    depth: int = 0,
    reversible: bool = True,
    evidence: str | None = None,
) -> WeakLinkSignal:
    return WeakLinkSignal(
        name=name,
        severity=severity,
        confidence=confidence,
        status=status,
        affects=affects,
        propagation_depth=depth,
        reversible=reversible,
        evidence=evidence,
    )


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _field(value: object, name: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def action_receipt_signals(
    receipt: object,
    *,
    verified: bool,
    verification_errors: Iterable[str] = (),
    verification_mode: str = "historical",
) -> tuple[WeakLinkSignal, ...]:
    """Translate a DDC Action Receipt into weak-link signals.

    verified must mean that the producer verifier ran successfully against
    independently supplied trust anchors. Historical verification never closes
    present-time freshness.
    """
    r = _mapping(receipt)
    if r is None:
        return (
            _signal(
                "action_receipt_format", 1.0, 1.0, WeakLinkStatus.UNRESOLVED,
                affects=("authority", "provenance", "execution"),
                reversible=False,
                evidence="receipt is not an object",
            ),
        )
    errors = tuple(str(x) for x in verification_errors)
    trust_closed = verified and not errors
    out: list[WeakLinkSignal] = [
        _signal(
            "action_receipt_trust",
            1.0,
            1.0,
            WeakLinkStatus.CLOSED if trust_closed else WeakLinkStatus.UNRESOLVED,
            affects=("authority", "provenance", "execution"),
            reversible=False,
            evidence="producer verification succeeded" if trust_closed
            else ("; ".join(errors[:4]) or "producer verification not established"),
        )
    ]

    decision = str(r.get("decision", ""))
    if decision == "ALLOW":
        decision_status = WeakLinkStatus.CLOSED if trust_closed else WeakLinkStatus.UNRESOLVED
    elif decision == "BLOCK":
        decision_status = WeakLinkStatus.CONTAINED if trust_closed else WeakLinkStatus.UNRESOLVED
    else:
        decision_status = WeakLinkStatus.UNRESOLVED
    out.append(_signal(
        "action_authorization", 0.95, 1.0, decision_status,
        affects=("authority", "execution"), depth=1, reversible=False,
        evidence=f"decision={decision or 'missing'}",
    ))

    assurance = _mapping(r.get("assurance")) or {}
    for dimension in _REQUIRED_RECEIPT_DIMENSIONS:
        entry = _mapping(assurance.get(dimension)) or {}
        passed = entry.get("status") == "PASS"
        if passed and trust_closed:
            status = WeakLinkStatus.CLOSED
        elif not passed and decision == "BLOCK" and trust_closed:
            status = WeakLinkStatus.CONTAINED
        else:
            status = WeakLinkStatus.UNRESOLVED
        out.append(_signal(
            f"receipt_{dimension}", 0.80, 0.95, status,
            affects=(dimension,), evidence=f"assurance.{dimension}={entry.get('status', 'missing')}",
        ))

    if trust_closed and verification_mode == "preflight":
        freshness = WeakLinkStatus.CLOSED
        freshness_evidence = "preflight verifier established current validity"
    else:
        freshness = WeakLinkStatus.UNRESOLVED
        freshness_evidence = (
            "historical verification does not establish current freshness"
            if verification_mode == "historical"
            else "current freshness not established"
        )
    out.append(_signal(
        "authorization_freshness", 0.95, 1.0, freshness,
        affects=("authority", "state", "execution"), depth=2, reversible=False,
        evidence=freshness_evidence,
    ))

    execution = _mapping(r.get("execution"))
    if decision == "ALLOW" and execution is not None and trust_closed:
        execution_status = WeakLinkStatus.CLOSED
    elif decision == "BLOCK" and execution is None and trust_closed:
        execution_status = WeakLinkStatus.CONTAINED
    else:
        execution_status = WeakLinkStatus.UNRESOLVED
    out.append(_signal(
        "action_execution_binding", 0.90, 1.0, execution_status,
        affects=("execution", "provenance"), depth=1, reversible=False,
        evidence="execution present" if execution is not None else "execution absent",
    ))
    return tuple(out)


def physical_gate_signals(
    decision: object,
    *,
    verified: bool,
    state_lineage_ok: bool | None = None,
) -> tuple[WeakLinkSignal, ...]:
    """Translate a Physical Gate decision after upstream signature/trust checks."""
    d = _mapping(decision)
    if d is None:
        return (
            _signal(
                "physical_gate_format", 1.0, 1.0, WeakLinkStatus.UNRESOLVED,
                affects=("physical", "state", "execution"), reversible=False,
            ),
        )
    payload = _mapping(d.get("payload")) or d
    disposition = str(payload.get("disposition", ""))

    out: list[WeakLinkSignal] = [
        _signal(
            "physical_gate_trust", 1.0, 1.0,
            WeakLinkStatus.CLOSED if verified else WeakLinkStatus.UNRESOLVED,
            affects=("physical", "state", "execution"), reversible=False,
            evidence="producer signature/trust verified" if verified else "decision trust not established",
        )
    ]
    if verified and disposition == "ALLOW":
        gate_status = WeakLinkStatus.CLOSED
    elif verified and disposition == "BLOCK":
        gate_status = WeakLinkStatus.CONTAINED
    else:
        gate_status = WeakLinkStatus.UNRESOLVED
    out.append(_signal(
        "physical_action_gate", 1.0, 1.0, gate_status,
        affects=("physical", "execution"), depth=1, reversible=False,
        evidence=f"disposition={disposition or 'missing'}",
    ))

    findings = payload.get("findings", [])
    if isinstance(findings, list):
        for item in findings[:64]:
            if not isinstance(item, Mapping):
                continue
            code = str(item.get("code") or item.get("reason") or "unknown").strip().lower()
            disp = str(item.get("disposition", disposition))
            status = (
                WeakLinkStatus.CONTAINED
                if verified and disp == "BLOCK"
                else WeakLinkStatus.UNRESOLVED
            )
            out.append(_signal(
                f"physical_finding:{code}", 0.90, 0.95, status,
                affects=("physical", "state", "execution"), depth=2,
                evidence=f"finding disposition={disp}",
            ))

    if state_lineage_ok is True and verified:
        lineage_status = WeakLinkStatus.CLOSED
        lineage_evidence = "monotonic state lineage accepted"
    elif state_lineage_ok is False:
        lineage_status = WeakLinkStatus.UNRESOLVED
        lineage_evidence = "state lineage rejected"
    else:
        lineage_status = WeakLinkStatus.UNRESOLVED
        lineage_evidence = "state lineage not supplied"
    out.append(_signal(
        "physical_state_lineage", 0.95, 1.0, lineage_status,
        affects=("state", "physical", "execution"), depth=2, reversible=False,
        evidence=lineage_evidence,
    ))
    return tuple(out)


def dsr_result_signals(verification: object) -> tuple[WeakLinkSignal, ...]:
    """Translate the output of DSR's fail-closed result verifier.

    Pass verifier output, not a raw signed result.
    """
    v = _mapping(verification)
    if v is None:
        return (
            _signal(
                "dsr_result_trust", 1.0, 1.0, WeakLinkStatus.UNRESOLVED,
                affects=("provenance", "execution"), reversible=False,
                evidence="DSR verifier output missing",
            ),
        )
    verified = v.get("state") == "VERIFIED"
    out = [
        _signal(
            "dsr_result_trust", 1.0, 1.0,
            WeakLinkStatus.CLOSED if verified else WeakLinkStatus.UNRESOLVED,
            affects=("provenance", "execution"), reversible=False,
            evidence=f"state={v.get('state', 'missing')}",
        )
    ]
    passed = verified and v.get("status") == "PASS" and v.get("exit_code") == 0
    out.append(_signal(
        "remote_execution_outcome", 0.90, 1.0,
        WeakLinkStatus.CLOSED if passed else WeakLinkStatus.UNRESOLVED,
        affects=("execution", "provenance"), depth=1, reversible=False,
        evidence=f"status={v.get('status', 'missing')}; exit_code={v.get('exit_code', 'missing')}",
    ))
    return tuple(out)


def renderdiff_signals(
    report: object,
    *,
    receipt_verified: bool,
) -> tuple[WeakLinkSignal, ...]:
    """Translate a RenderDiff report after receipt/seal verification."""
    r = _mapping(report)
    if r is None:
        return (
            _signal(
                "renderdiff_format", 1.0, 1.0, WeakLinkStatus.UNRESOLVED,
                affects=("representation", "semantic"), reversible=False,
            ),
        )
    views = _mapping(r.get("views")) or {}
    assessment = _mapping(views.get("assurance")) or {}
    summary = _mapping(r.get("summary")) or {}
    material = bool(assessment.get("material_divergence", summary.get("material_divergence", False)))
    complete = bool(assessment.get("complete", False))
    coverage = _mapping(assessment.get("coverage")) or {}

    out = [
        _signal(
            "renderdiff_receipt_trust", 0.95, 1.0,
            WeakLinkStatus.CLOSED if receipt_verified else WeakLinkStatus.UNRESOLVED,
            affects=("representation", "provenance"), reversible=False,
            evidence="receipt/seal verified" if receipt_verified else "receipt/seal trust not established",
        )
    ]
    divergence_status = (
        WeakLinkStatus.CLOSED
        if receipt_verified and not material
        else WeakLinkStatus.UNRESOLVED
    )
    out.append(_signal(
        "representation_divergence", 0.95, 1.0, divergence_status,
        affects=("representation", "semantic", "execution"), depth=2,
        evidence=f"material_divergence={material}",
    ))

    unavailable = sorted(k for k, value in coverage.items() if value == "unavailable")
    coverage_status = (
        WeakLinkStatus.CLOSED
        if receipt_verified and complete
        else WeakLinkStatus.UNRESOLVED
    )
    out.append(_signal(
        "representation_observer_coverage", 0.60, 0.90, coverage_status,
        affects=("representation", "semantic"), depth=1,
        evidence="complete observer coverage" if coverage_status is WeakLinkStatus.CLOSED
        else ("unavailable=" + ",".join(unavailable[:12]) if unavailable else "assessment declares incomplete coverage"),
    ))
    return tuple(out)


def transition_closure_signals(result: object) -> tuple[WeakLinkSignal, ...]:
    """Translate Authorization Transition Closure verifier output."""
    disposition = str(_field(result, "disposition", ""))
    if "." in disposition:
        disposition = disposition.rsplit(".", 1)[-1]
    reason = str(_field(result, "reason", ""))
    if disposition == "CLOSED":
        status = WeakLinkStatus.CLOSED
        severity = 1.0
    elif disposition == "FAILED":
        status = WeakLinkStatus.UNRESOLVED
        severity = 1.0
    else:
        status = WeakLinkStatus.UNRESOLVED
        severity = 0.85
    return (
        _signal(
            "authorization_transition_closure", severity, 1.0, status,
            affects=("authority", "state", "execution", "provenance"),
            depth=3, reversible=False,
            evidence=reason or f"disposition={disposition or 'missing'}",
        ),
    )


def analyze_evidence_bundle(
    *,
    action_receipt: object | None = None,
    action_receipt_verified: bool = False,
    action_receipt_errors: Iterable[str] = (),
    action_receipt_mode: str = "historical",
    physical_decision: object | None = None,
    physical_verified: bool = False,
    physical_state_lineage_ok: bool | None = None,
    dsr_verification: object | None = None,
    renderdiff_report: object | None = None,
    renderdiff_receipt_verified: bool = False,
    transition_result: object | None = None,
    analyzer: WeakLinkAnalyzer | None = None,
) -> WeakLinkReport:
    """Combine verified producer evidence into one Radial weak-link report."""
    signals: list[WeakLinkSignal] = []
    if action_receipt is not None:
        signals.extend(action_receipt_signals(
            action_receipt,
            verified=action_receipt_verified,
            verification_errors=action_receipt_errors,
            verification_mode=action_receipt_mode,
        ))
    if physical_decision is not None:
        signals.extend(physical_gate_signals(
            physical_decision,
            verified=physical_verified,
            state_lineage_ok=physical_state_lineage_ok,
        ))
    if dsr_verification is not None:
        signals.extend(dsr_result_signals(dsr_verification))
    if renderdiff_report is not None:
        signals.extend(renderdiff_signals(
            renderdiff_report,
            receipt_verified=renderdiff_receipt_verified,
        ))
    if transition_result is not None:
        signals.extend(transition_closure_signals(transition_result))
    return (analyzer or WeakLinkAnalyzer()).analyze(signals)
