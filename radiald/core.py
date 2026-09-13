from __future__ import annotations

from dataclasses import dataclass
import threading
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from typing import Callable, Generic, TypeVar

from .canonical import stable_digest, typed_identity

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
    join_attempts: int
    timed_out_joins: int
    rejected_shared_outputs: int

    @property
    def work_avoided_ratio(self) -> float:
        if self.logical_requests == 0:
            return 0.0
        return 1.0 - (self.physical_executions / self.logical_requests)


class RadialExecutor:
    """Coalesce identical deterministic work while preserving authority boundaries.

    Sharing is allowed only when both authority and work key have identical,
    type-preserving identities. Results are shared only while work is in flight;
    RadialD is deliberately not a persistent cache.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight: dict[tuple[str, str], Future[WorkResult[object]]] = {}
        self._active_key_authorities: dict[str, set[str]] = {}
        self._logical_requests = 0
        self._physical_executions = 0
        self._shared_requests = 0
        self._refused_cross_authority = 0
        self._join_attempts = 0
        self._timed_out_joins = 0
        self._rejected_shared_outputs = 0

    @staticmethod
    def _digest(value: object) -> str:
        return stable_digest(value)

    def run(
        self,
        *,
        authority: object,
        work_key: object,
        compute: Callable[[], T],
        verifier: Callable[[T], bool] | None = None,
        join_timeout: float | None = None,
    ) -> WorkResult[T]:
        """Execute or join one deterministic unit of work.

        The work key must completely identify deterministic inputs and semantics.
        Different authorities never share. A joiner's verifier is always applied
        locally before a shared value is released to that caller.
        """
        if join_timeout is not None and join_timeout < 0:
            raise ValueError("join_timeout must be non-negative or None")

        authority_id = typed_identity(authority)
        work_id = typed_identity(work_key)
        composite = (authority_id, work_id)
        owner = False

        with self._lock:
            self._logical_requests += 1
            existing = self._inflight.get(composite)
            if existing is not None:
                self._join_attempts += 1
                future = existing
            else:
                authorities = self._active_key_authorities.setdefault(work_id, set())
                if authorities and authority_id not in authorities:
                    self._refused_cross_authority += 1
                authorities.add(authority_id)
                future = Future()
                self._inflight[composite] = future
                self._physical_executions += 1
                owner = True

        if not owner:
            try:
                result = future.result(timeout=join_timeout)
            except FutureTimeoutError as exc:
                with self._lock:
                    self._timed_out_joins += 1
                raise TimeoutError("timed out waiting for shared RadialD work") from exc
            value = result.value  # type: ignore[assignment]
            if verifier is not None and not verifier(value):  # type: ignore[arg-type]
                with self._lock:
                    self._rejected_shared_outputs += 1
                raise ValueError("RadialD verifier rejected shared output")
            with self._lock:
                self._shared_requests += 1
            return WorkResult(value=value, digest=result.digest, shared=True)  # type: ignore[arg-type]

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
                authorities = self._active_key_authorities.get(work_id)
                if authorities is not None:
                    authorities.discard(authority_id)
                    if not authorities:
                        self._active_key_authorities.pop(work_id, None)

    def stats(self) -> WorkStats:
        with self._lock:
            return WorkStats(
                logical_requests=self._logical_requests,
                physical_executions=self._physical_executions,
                shared_requests=self._shared_requests,
                refused_cross_authority=self._refused_cross_authority,
                join_attempts=self._join_attempts,
                timed_out_joins=self._timed_out_joins,
                rejected_shared_outputs=self._rejected_shared_outputs,
            )
