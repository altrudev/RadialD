from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import threading
from concurrent.futures import Future
from typing import Callable, Generic, Hashable, TypeVar

T = TypeVar("T")


def _canonical_value(value: object) -> object:
    """Return a type-preserving deterministic representation.

    RadialD uses fingerprints in execution lineage. Unsupported Python objects
    fail closed rather than falling back to repr(), because repr may omit hidden
    state or include process-specific addresses.
    """
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("RadialD cannot fingerprint non-finite floats")
        return ["float", value.hex()]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, bytes):
        return ["bytes", value.hex()]
    if isinstance(value, list):
        return ["list", [_canonical_value(item) for item in value]]
    if isinstance(value, tuple):
        return ["tuple", [_canonical_value(item) for item in value]]
    if isinstance(value, dict):
        items = [
            [_canonical_value(key), _canonical_value(item)]
            for key, item in value.items()
        ]
        items.sort(
            key=lambda pair: json.dumps(
                pair[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        )
        return ["dict", items]
    if isinstance(value, set):
        items = [_canonical_value(item) for item in value]
        items.sort(
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        )
        return ["set", items]
    if isinstance(value, frozenset):
        items = [_canonical_value(item) for item in value]
        items.sort(
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        )
        return ["frozenset", items]
    raise TypeError(
        f"RadialD deterministic fingerprint requires a supported built-in value, got {type(value).__name__}"
    )


def stable_digest(value: object) -> str:
    encoded = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True)
class WorkResult(Generic[T]):
    value: T
    digest: str
    shared: bool


@dataclass(frozen=True)
class WorkStats:
    logical_requests: int
    physical_executions: int
    shared_requests: int
    refused_cross_authority: int

    @property
    def work_avoided_ratio(self) -> float:
        if self.logical_requests == 0:
            return 0.0
        return 1.0 - (self.physical_executions / self.logical_requests)


class RadialExecutor:
    """Coalesce identical deterministic work while preserving authority boundaries.

    Sharing is allowed only when both `authority` and `work_key` are equal.
    Results are shared only while work is in flight; RadialD is deliberately not
    a persistent cache.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight: dict[tuple[Hashable, Hashable], Future[WorkResult[object]]] = {}
        self._active_key_authorities: dict[Hashable, set[Hashable]] = {}
        self._logical_requests = 0
        self._physical_executions = 0
        self._shared_requests = 0
        self._refused_cross_authority = 0

    @staticmethod
    def _digest(value: object) -> str:
        return stable_digest(value)

    def run(
        self,
        *,
        authority: Hashable,
        work_key: Hashable,
        compute: Callable[[], T],
        verifier: Callable[[T], bool] | None = None,
        verifier_key: Hashable | None = None,
    ) -> WorkResult[T]:
        """Execute or join one deterministic unit of work.

        Callers are responsible for choosing a `work_key` that completely
        identifies deterministic inputs. Different authorities never share.
        """
        if verifier is None and verifier_key is not None:
            raise ValueError("verifier_key requires verifier")
        if verifier is None:
            verifier_identity = ("none",)
        elif verifier_key is not None:
            verifier_identity = ("key", verifier_key)
        else:
            verifier_identity = ("callable-id", id(verifier))
        composite = (authority, work_key, verifier_identity)
        active_key = (work_key, verifier_identity)
        owner = False

        with self._lock:
            self._logical_requests += 1
            existing = self._inflight.get(composite)
            if existing is not None:
                self._shared_requests += 1
                future = existing
            else:
                authorities = self._active_key_authorities.setdefault(active_key, set())
                if authorities and authority not in authorities:
                    self._refused_cross_authority += 1
                authorities.add(authority)
                future = Future()
                self._inflight[composite] = future
                self._physical_executions += 1
                owner = True

        if not owner:
            result = future.result()
            return WorkResult(value=result.value, digest=result.digest, shared=True)  # type: ignore[arg-type]

        try:
            value = compute()
            if verifier is not None and not verifier(value):
                raise ValueError("RadialD verifier rejected computed output")
            result: WorkResult[T] = WorkResult(
                value=value, digest=self._digest(value), shared=False
            )
            future.set_result(result)  # type: ignore[arg-type]
            return result
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._inflight.pop(composite, None)
                authorities = self._active_key_authorities.get(active_key)
                if authorities is not None:
                    authorities.discard(authority)
                    if not authorities:
                        self._active_key_authorities.pop(active_key, None)

    def stats(self) -> WorkStats:
        with self._lock:
            return WorkStats(
                logical_requests=self._logical_requests,
                physical_executions=self._physical_executions,
                shared_requests=self._shared_requests,
                refused_cross_authority=self._refused_cross_authority,
            )
