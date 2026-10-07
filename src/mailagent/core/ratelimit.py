"""Лимит запросов на пользователя (02-security T11): скользящее окно в памяти процесса."""
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    # ponytail: память процесса, один воркер; при нескольких — счётчики в Postgres/Redis
    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic):
        self._limit, self._window, self._clock = limit, window, clock
        self._hits: dict[tuple[str, str], deque[float]] = {}

    def allow(self, key: tuple[str, str]) -> bool:
        now = self._clock()
        q = self._hits.setdefault(key, deque())
        while q and q[0] <= now - self._window:
            q.popleft()
        if len(q) >= self._limit:
            return False
        q.append(now)
        if len(self._hits) > 10_000:  # не копим ключи ушедших пользователей
            self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - self._window}
        return True
