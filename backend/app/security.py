import re
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Header, HTTPException, Request

from . import config

_VISITOR_RE = re.compile(r"[0-9a-fA-F-]{32,64}")


def get_owner_id(x_visitor_id: Optional[str] = Header(default=None)) -> Optional[str]:
    """Anonymous per-browser id (a random UUID the frontend generates and sends).
    128 random bits make it unguessable, so it works like a private key for that
    browser's history. Returns None if missing or malformed."""
    if x_visitor_id:
        value = x_visitor_id.strip()
        if _VISITOR_RE.fullmatch(value):
            return value.lower()
    return None


def client_ip(request: Request) -> str:
    if config.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # The LAST entry is the one your own proxy added. Earlier ones are client-supplied.
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _human(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} seconds"
    if seconds < 5400:
        return f"{round(seconds / 60)} minutes"
    return f"{round(seconds / 3600)} hours"


class RateLimiter:
    """In-memory sliding window. Fine for one server process. With several workers or
    instances each keeps its own counts, so move to Redis if you scale out."""

    def __init__(self, name: str, limit: int, window_seconds: int, message: str,
                 per_client: bool = True, clock=time.monotonic):
        self.name = name
        self.limit = limit
        self.window = window_seconds
        self.message = message
        self.per_client = per_client
        self.clock = clock
        self._hits = defaultdict(deque)  # key -> deque[(timestamp, cost)]

    def check(self, request: Request, cost: int = 1) -> None:
        if self.limit <= 0:  # disabled
            return
        now = self.clock()
        cutoff = now - self.window
        key = client_ip(request) if self.per_client else "global"
        hits = self._hits[key]
        while hits and hits[0][0] <= cutoff:
            hits.popleft()

        if sum(c for _, c in hits) + cost > self.limit:
            retry = int(hits[0][0] + self.window - now) + 1 if hits else int(self.window)
            retry = max(1, retry)
            raise HTTPException(
                status_code=429,
                detail=f"{self.message} Try again in {_human(retry)}.",
                headers={"Retry-After": str(retry)},
            )

        hits.append((now, cost))
        if len(self._hits) > 10_000:  # don't let the table grow forever
            for k in [k for k, d in self._hits.items() if not d or d[-1][0] <= cutoff]:
                del self._hits[k]

    async def __call__(self, request: Request) -> None:
        self.check(request)


scan_limiter = RateLimiter("scan", config.RATE_LIMIT_SCANS_PER_MIN, 60, "You're scanning too fast.")
batch_limiter = RateLimiter("batch", config.RATE_LIMIT_BATCHES_PER_HOUR, 3600, "Batch scans are limited.")
read_limiter = RateLimiter("read", config.RATE_LIMIT_READS_PER_MIN, 60, "Too many requests.")
daily_cap = RateLimiter(
    "daily", config.GLOBAL_SCANS_PER_DAY, 86400,
    "CyberGuardian has reached its daily scan limit.", per_client=False,
)