from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import base64
import json
import math
import threading
from concurrent.futures import Future
from typing import Callable, Generic, Hashable, TypeVar

T = TypeVar("T")


def _canonical_value(value: object, *, _seen: set[int] | None = None, _depth: int = 0) -> object:
    """Return a type-preserving deterministic representation.

    Unsupported objects, reference cycles, and excessive nesting fail closed.
    This avoids repr()-based ambiguity and bounds pathological recursion.
    """
    if _depth > 128:
        raise TypeError("RadialD fingerprint nesting exceeds 128 levels")
    if _seen is None:
        _seen = set()
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
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, list):
        identity = id(value)
        if identity in _seen:
            raise TypeError("RadialD cannot fingerprint cyclic containers")
        _seen.add(identity)
        try:
            return ["list", [_canonical_value(item, _seen=_seen, _depth=_depth + 1) for item in value]]
        finally:
            _seen.remove(identity)
    if isinstance(value, tuple):
        identity = id(value)
        if identity in _seen:
            raise TypeError("RadialD cannot fingerprint cyclic containers")
        _seen.add(identity)
        try:
            return ["tuple", [_canonical_value(item, _seen=_seen, _depth=_depth + 1) for item in value]]
        finally:
            _seen.remove(identity)
    if isinstance(value, dict):
        identity = id(value)
        if identity in _seen:
            raise TypeError("RadialD cannot fingerprint cyclic containers")
        _seen.add(identity)
        try:
            items = [
                [
                    _canonical_value(key, _seen=_seen, _depth=_depth + 1),
                    _canonical_value(item, _seen=_seen, _depth=_depth + 1),
                ]
                for key, item in value.items()
            ]
            items.sort(
                key=lambda pair: json.dumps(
                    pair[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
            )
            return ["dict", items]
        finally:
            _seen.remove(identity)
    if isinstance(value, set):
        identity = id(value)
        if identity in _seen:
            raise TypeError("RadialD cannot fingerprint cyclic containers")
        _seen.add(identity)
        try:
            items = [
                _canonical_value(item, _seen=_seen, _depth=_depth + 1)
                for item in value
            ]
            items.sort(
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
            )
            return ["set", items]
        finally:
            _seen.remove(identity)
    if isinstance(value, frozenset):
        identity = id(value)
        if identity in _seen:
            raise TypeError("RadialD cannot fingerprint cyclic containers")
        _seen.add(identity)
        try:
            items = [
                _canonical_value(item, _seen=_seen, _depth=_depth + 1)
                for item in value
            ]
            items.sort(
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
            )
            return ["frozenset", items]
        finally:
            _seen.remove(identity)
    raise TypeError(
        f"RadialD deterministic fingerprint requires a supported built-in value, got {type(value).__name__}"
    )


def stable_digest(value: object) -> str:
    encoded = json.dumps(
        ["radiald-fingerprint-v2", _canonical_value(value)],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkResult(Generic[T]):
    value: T
    digest: str
    shared: bool


@dataclass(frozen=True, slots=True)
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

    Sharing requires equal authority, work identity, and verifier contract.
    Results are retained only while work is in flight; RadialD is deliberately
    not a persistent cache.
    """

    __slots__ = (
        "_lock",
        "_inflight",
        "_active_key_authorities",
        "_logical_requests",
        "_physical_executions",
        "_shared_requests",
        "_refused_cross_authority",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight: dict[
            tuple[Hashable, Hashable, object], Future[WorkResult[object]]
        ] = {}
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
