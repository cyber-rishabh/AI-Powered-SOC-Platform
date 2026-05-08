"""
cti_cache.py — In-memory IOC cache for CTI enrichment results.
TTL: 1 hour | Thread-safe | SOC-scale
"""

import time
import threading
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS: int = 3600  # 1 hour

_cache: dict[str, dict] = {}
_lock: threading.Lock = threading.Lock()

# TODO:
# Add periodic background cleanup task for expired IOC entries
# once FastAPI startup/shutdown lifecycle hooks are integrated.


def get_cached_cti(ip: str) -> Optional[dict]:
    """
    Return cached CTI data for an IP if present and not expired.
    Returns None on cache miss or expiry.
    """
    with _lock:
        entry = _cache.get(ip)
        if entry is None:
            logger.debug("[CTI] CACHE MISS ip=%s", ip)
            return None

        age = time.time() - entry["cached_at"]
        if age > _CACHE_TTL_SECONDS:
            logger.info("[CTI] CACHE EXPIRED ip=%s age=%.0fs", ip, age)
            del _cache[ip]
            return None

        logger.info("[CTI] CACHE HIT ip=%s age=%.0fs", ip, age)
        return entry["data"]


def set_cached_cti(ip: str, data: dict) -> None:
    """
    Store CTI enrichment result in cache with current timestamp.
    """
    with _lock:
        _cache[ip] = {
            "data": data,
            "cached_at": time.time(),
        }
        logger.info("[CTI] CACHE SET ip=%s cache_size=%d", ip, len(_cache))


def clear_expired_cache() -> None:
    """
    Evict all entries whose TTL has elapsed.
    Safe to call periodically as a background cleanup task.
    """
    now = time.time()
    with _lock:
        expired_keys = [
            ip for ip, entry in _cache.items()
            if (now - entry["cached_at"]) > _CACHE_TTL_SECONDS
        ]
        for ip in expired_keys:
            del _cache[ip]

    if expired_keys:
        logger.info(
            "[CTI] CACHE CLEANUP evicted=%d keys=%s",
            len(expired_keys),
            expired_keys,
        )
    else:
        logger.debug("[CTI] CACHE CLEANUP no expired entries found")


def get_cache_stats() -> dict:
    """
    Return diagnostic stats about current cache state.

    Returns:
        {
            "cache_size": int,
            "oldest_entry_age": float | None,   # seconds
            "newest_entry_age": float | None,   # seconds
        }
    """
    now = time.time()
    with _lock:
        if not _cache:
            return {
                "cache_size": 0,
                "oldest_entry_age": None,
                "newest_entry_age": None,
            }

        ages = [now - entry["cached_at"] for entry in _cache.values()]
        stats = {
            "cache_size": len(_cache),
            "oldest_entry_age": round(max(ages), 2),
            "newest_entry_age": round(min(ages), 2),
        }

    logger.debug("[CTI] CACHE STATS %s", stats)
    return stats
