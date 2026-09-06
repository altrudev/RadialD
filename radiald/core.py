from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import threading
from concurrent.futures import Future
from typing import Callable, Generic, Hashable, TypeVar

T = TypeVar("T")


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
        try:
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        except (TypeError, ValueError):
            encoded = repr(value).encode("utf-8")
        return sha256(encoded).hexdigest()

    def run(
        self,
        *,
        authority: Hashable,
        work_key: Hashable,
        compute: Callable[[], T],
        verifier: Callable[[T], bool] | None = None,
    ) -> WorkResult[T]:
        """Execute or join one deterministic unit of work.

        Callers are responsible for choosing a `work_key` that completely
        identifies deterministic inputs. Different authorities never share.
        """
        composite = (authority, work_key)
        owner = False

        with self._lock:
            self._logical_requests += 1
            existing = self._inflight.get(composite)
            if existing is not None:
                self._shared_requests += 1
                future = existing
            else:
                authorities = self._active_key_authorities.setdefault(work_key, set())
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
                authorities = self._active_key_authorities.get(work_key)
                if authorities is not None:
                    authorities.discard(authority)
                    if not authorities:
                        self._active_key_authorities.pop(work_key, None)

    def stats(self) -> WorkStats:
        with self._lock:
            return WorkStats(
                logical_requests=self._logical_requests,
                physical_executions=self._physical_executions,
                shared_requests=self._shared_requests,
                refused_cross_authority=self._refused_cross_authority,
            )
