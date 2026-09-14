"""RadialD public API."""

from .adapters import (
    action_receipt_signals,
    analyze_evidence_bundle,
    dsr_result_signals,
    physical_gate_signals,
    renderdiff_signals,
    transition_closure_signals,
)
from .fabric import (
    AssuranceFabricResult,
    BindingReport,
    EvidenceEnvelope,
    EvidencePolicy,
    analyze_assurance_fabric,
    bind_evidence,
    contradiction_signals,
    policy_signals,
)
from .receipt import (
    make_assurance_receipt,
    seal_assurance_receipt,
    verify_assurance_receipt,
)
from .canonical import CanonicalizationError, stable_digest
from .core import RadialExecutor, WorkResult, WorkStats
from .graph import GraphResult, NodeTrace, RadialGraphExecutor, Stage
from .weaklink import (
    SafeAutonomy,
    WeakLinkAnalyzer,
    WeakLinkPolicy,
    WeakLinkReport,
    WeakLinkSignal,
    WeakLinkStatus,
)

__all__ = [
    "AssuranceFabricResult",
    "BindingReport",
    "CanonicalizationError",
    "EvidenceEnvelope",
    "EvidencePolicy",
    "GraphResult",
    "NodeTrace",
    "RadialExecutor",
    "RadialGraphExecutor",
    "SafeAutonomy",
    "Stage",
    "WeakLinkAnalyzer",
    "WeakLinkPolicy",
    "WeakLinkReport",
    "WeakLinkSignal",
    "WeakLinkStatus",
    "WorkResult",
    "WorkStats",
    "action_receipt_signals",
    "analyze_assurance_fabric",
    "analyze_evidence_bundle",
    "bind_evidence",
    "contradiction_signals",
    "dsr_result_signals",
    "physical_gate_signals",
    "make_assurance_receipt",
    "policy_signals",
    "renderdiff_signals",
    "seal_assurance_receipt",
    "stable_digest",
    "transition_closure_signals",
    "verify_assurance_receipt",
]
__version__ = "0.4.0"
