"""RadialD public API."""

from .adapters import (
    action_receipt_signals,
    analyze_evidence_bundle,
    dsr_result_signals,
    physical_gate_signals,
    renderdiff_signals,
    transition_closure_signals,
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
    "CanonicalizationError",
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
    "analyze_evidence_bundle",
    "dsr_result_signals",
    "physical_gate_signals",
    "renderdiff_signals",
    "stable_digest",
    "transition_closure_signals",
]
__version__ = "0.4.0"
