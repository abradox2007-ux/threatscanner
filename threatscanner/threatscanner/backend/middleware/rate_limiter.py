"""
Rate limiter middleware — uses Redis when available, falls back to in-memory.
Implements a sliding-window counter per client IP.
"""
import time
from collections import defaultdict, deque
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

# In-memory fallback store  {ip: deque of timestamps}
_store: dict[str, deque] = defaultdict(deque)

try:
    import redis.asyncio as aioredis
    from config import REDIS_URL
    _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    USE_REDIS = True
except Exception:
    _redis_client = None
    USE_REDIS = False


class RateLimitMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request, call_next):
        # Only rate-limit the scan endpoints
        if not request.url.path.startswith("/api/scan"):
            return await call_next(request)

        client_ip = _get_ip(request)
        allowed = await self._check(client_ip)

        if not allowed:
            return JSONResponse(
                {"error": f"Rate limit exceeded — max {RATE_LIMIT_REQUESTS} requests "
                           f"per {RATE_LIMIT_WINDOW} seconds. Try again shortly."},
                status_code=429,
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )

        response = await call_next(request)
        return response

    async def _check(self, ip: str) -> bool:
        if USE_REDIS and _redis_client:
            try:
                return await _redis_check(ip)
            except Exception:
                # Graceful fallback to in-memory limiting if Redis is unreachable
                return _memory_check(ip)
        return _memory_check(ip)


async def _redis_check(ip: str) -> bool:
    key = f"rl:{ip}"
    now = int(time.time())
    window_start = now - RATE_LIMIT_WINDOW
    pipe = _redis_client.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zadd(key, {str(now) + "_" + str(time.time_ns()): now})
    pipe.zcard(key)
    pipe.expire(key, RATE_LIMIT_WINDOW)
    results = await pipe.execute()
    return results[2] <= RATE_LIMIT_REQUESTS


def _memory_check(ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    q = _store[ip]
    while q and q[0] < window_start:
        q.popleft()
    if len(q) >= RATE_LIMIT_REQUESTS:
        return False
    q.append(now)
    return True


def _get_ip(request) -> str:
    # Respect X-Forwarded-For when behind a trusted proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
