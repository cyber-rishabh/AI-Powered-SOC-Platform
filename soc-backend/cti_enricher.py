"""
cti_enricher.py — Async Cyber Threat Intelligence enrichment service.
Sources: AbuseIPDB, AlienVault OTX (with mock mode fallback).
"""

import asyncio
import ipaddress
import logging
import os
import random
import time
import threading
from datetime import datetime, timezone
from typing import Optional

import httpx

from cti_cache import get_cached_cti, set_cached_cti

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# ENVIRONMENT CONFIG
# ─────────────────────────────────────────────

ABUSEIPDB_KEY: str = os.getenv("ABUSEIPDB_KEY", "")
OTX_KEY: str = os.getenv("OTX_KEY", "")

_MOCK_CTI_ENV = os.getenv("MOCK_CTI")
if _MOCK_CTI_ENV is None:
    MOCK_CTI: bool = not (ABUSEIPDB_KEY or OTX_KEY)
else:
    MOCK_CTI = _MOCK_CTI_ENV.lower() in ("1", "true", "yes")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

COOLDOWN_DURATION_SECONDS: int = 300  # 5 minutes

# ─────────────────────────────────────────────
# RATE LIMIT COOLDOWN STATE
# ─────────────────────────────────────────────

_cooldown_lock = threading.Lock()
_cooldown_until: float = 0.0  # epoch seconds


def _trigger_cooldown() -> None:
    global _cooldown_until
    with _cooldown_lock:
        _cooldown_until = time.time() + COOLDOWN_DURATION_SECONDS
    logger.warning(
        "[CTI] RATE LIMIT triggered — cooldown active for %ds",
        COOLDOWN_DURATION_SECONDS,
    )


def _cooldown_remaining() -> float:
    """Return seconds remaining in cooldown, or 0.0 if not active."""
    with _cooldown_lock:
        remaining = _cooldown_until - time.time()
    return max(remaining, 0.0)


def _is_in_cooldown() -> bool:
    return _cooldown_remaining() > 0.0


# ─────────────────────────────────────────────
# PRIVATE IP FILTERING
# ─────────────────────────────────────────────

def _is_routable_public_ip(ip: str) -> bool:
    """
    Return True only for globally routable, non-special-purpose IPs.
    Returns False for private, loopback, multicast, link-local, or invalid.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("[CTI] Invalid IP format ip=%s — skipping", ip)
        return False

    if ":" in ip:
        logger.info("[CTI] IPv6 IOC detected ip=%s", ip)

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return False

    return True


def _private_ip_result() -> dict:
    return {"verdict": "PRIVATE_IP", "abuse_score": 0}


# ─────────────────────────────────────────────
# MOCK DATA GENERATOR
# ─────────────────────────────────────────────

_MOCK_ISPS = [
    "Tor Exit Node", "DigitalOcean LLC", "Linode LLC",
    "OVH SAS", "AS-CHOOPA", "Hetzner Online GmbH",
    "Amazon AWS", "ColoCrossing", "ServerMania",
]

_MOCK_COUNTRIES = ["DE", "RU", "CN", "NL", "US", "BR", "UA", "RO", "FR"]

_MOCK_PULSES = [
    "Cobalt Strike Infra", "Emotet C2", "Credential Access Activity",
    "SSH Brute Force Campaign", "Mirai Botnet", "Log4Shell Exploitation",
    "LockBit Ransomware", "APT29 Infrastructure", "Phishing Kit Distribution",
    "Proxy Anonymization Network", "RedLine Stealer", "Qakbot Campaign",
]


def _generate_mock_cti(ip: str) -> dict:
    """Return randomized but plausible CTI data for testing/demo purposes."""
    abuse_score = random.choices(
        population=[random.randint(0, 20), random.randint(30, 65), random.randint(70, 89), random.randint(90, 100)],
        weights=[25, 30, 25, 20],
        k=1,
    )[0]

    pulse_count = random.choices(
        population=[random.randint(0, 5), random.randint(6, 20), random.randint(21, 60)],
        weights=[40, 40, 20],
        k=1,
    )[0]

    related_pulses = random.sample(_MOCK_PULSES, k=min(pulse_count, len(_MOCK_PULSES))) if pulse_count > 0 else []

    verdict = _compute_verdict(abuse_score, pulse_count)

    data = {
        "abuse_score": abuse_score,
        "country": random.choice(_MOCK_COUNTRIES),
        "isp": random.choice(_MOCK_ISPS),
        "pulse_count": pulse_count,
        "total_reports": random.randint(abuse_score * 5, abuse_score * 15 + 1),
        "verdict": verdict,
        "related_pulses": related_pulses,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "source": "mock",
    }

    logger.info(
        "[CTI] MOCK MODE generated ip=%s verdict=%s abuse_score=%d",
        ip, verdict, abuse_score,
    )
    return data


# ─────────────────────────────────────────────
# VERDICT ENGINE
# ─────────────────────────────────────────────

def _compute_verdict(abuse_score: int, pulse_count: int) -> str:
    if abuse_score >= 90 or pulse_count >= 25:
        return "CRITICAL"
    if abuse_score >= 70:
        return "MALICIOUS"
    if abuse_score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"


# ─────────────────────────────────────────────
# ABUSEIPDB LOOKUP
# ─────────────────────────────────────────────

async def _lookup_abuseipdb(client: httpx.AsyncClient, ip: str) -> dict:
    """Query AbuseIPDB and return normalized result dict."""
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = await client.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=httpx.Timeout(timeout=8.0, connect=3.0))

        if response.status_code == 429:
            logger.warning("[CTI] AbuseIPDB rate limited (429) ip=%s", ip)
            _trigger_cooldown()
            return {}

        response.raise_for_status()
        payload = response.json().get("data", {})

        result = {
            "abuse_score": payload.get("abuseConfidenceScore", 0),
            "country": payload.get("countryCode", "XX"),
            "total_reports": payload.get("totalReports", 0),
            "isp": payload.get("isp", "Unknown"),
        }
        logger.info("[CTI] AbuseIPDB lookup success ip=%s score=%d", ip, result["abuse_score"])
        return result

    except httpx.HTTPStatusError as exc:
        logger.error("[CTI] AbuseIPDB HTTP error ip=%s status=%d", ip, exc.response.status_code)
        return {}
    except Exception as exc:
        logger.error("[CTI] AbuseIPDB exception ip=%s error=%s", ip, exc)
        return {}


# ─────────────────────────────────────────────
# ALIENVAULT OTX LOOKUP
# ─────────────────────────────────────────────

async def _lookup_otx(client: httpx.AsyncClient, ip: str) -> dict:
    """Query AlienVault OTX and return normalized pulse data."""
    url = OTX_URL.format(ip=ip)
    headers = {"X-OTX-API-KEY": OTX_KEY}

    try:
        response = await client.get(url, headers=headers, timeout=httpx.Timeout(timeout=8.0, connect=3.0))

        if response.status_code == 429:
            logger.warning("[CTI] OTX rate limited (429) ip=%s", ip)
            _trigger_cooldown()
            return {}

        response.raise_for_status()
        payload = response.json()

        pulses = payload.get("pulse_info", {}).get("pulses", [])
        pulse_names = [p.get("name", "") for p in pulses if p.get("name")]

        result = {
            "pulse_count": len(pulses),
            "related_pulses": pulse_names[:5],  # cap to 5 — avoids ES bloat and dashboard noise
        }
        logger.info("[CTI] OTX lookup success ip=%s pulse_count=%d", ip, result["pulse_count"])
        return result

    except httpx.HTTPStatusError as exc:
        logger.error("[CTI] OTX HTTP error ip=%s status=%d", ip, exc.response.status_code)
        return {}
    except Exception as exc:
        logger.error("[CTI] OTX exception ip=%s error=%s", ip, exc)
        return {}


# ─────────────────────────────────────────────
# LIVE ENRICHMENT PIPELINE
# ─────────────────────────────────────────────

async def _enrich_live(ip: str) -> dict:
    """
    Run parallel AbuseIPDB + OTX lookups and merge results.
    Returns a safe fallback on any failure.
    """
    async with httpx.AsyncClient() as client:
        abuse_task = _lookup_abuseipdb(client, ip) if ABUSEIPDB_KEY else asyncio.sleep(0, result={})
        otx_task = _lookup_otx(client, ip) if OTX_KEY else asyncio.sleep(0, result={})

        abuse_result, otx_result = await asyncio.gather(abuse_task, otx_task)

    # Merge
    abuse_score = abuse_result.get("abuse_score", 0)
    pulse_count = otx_result.get("pulse_count", 0)
    verdict = _compute_verdict(abuse_score, pulse_count)

    return {
        "abuse_score": abuse_score,
        "country": abuse_result.get("country", "XX"),
        "isp": abuse_result.get("isp", "Unknown"),
        "total_reports": abuse_result.get("total_reports", 0),
        "pulse_count": pulse_count,
        "related_pulses": otx_result.get("related_pulses", []),
        "verdict": verdict,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "source": "live",
    }


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

async def enrich_ip(ip: str) -> dict:
    """
    Enrich a public IP with CTI data.

    Flow:
      1. Skip private/invalid IPs immediately.
      2. Return cached result if available.
      3. If MOCK_CTI=true, return mock data.
      4. If in rate-limit cooldown, return RATE_LIMITED.
      5. Run live AbuseIPDB + OTX lookups in parallel.
      6. Cache and return result.

    Always returns a dict — never raises.
    """
    # 0. Empty/None IP guard
    if not ip:
        logger.warning("[CTI] enrich_ip called with empty IP — skipping")
        return {"verdict": "NO_IP", "abuse_score": 0}

    # 1. Private IP guard
    if not _is_routable_public_ip(ip):
        logger.info("[CTI] Private IP skipped ip=%s", ip)
        return _private_ip_result()

    # 2. Cache check
    cached = get_cached_cti(ip)
    if cached is not None:
        return cached

    # 3. Mock mode
    if MOCK_CTI:
        logger.info("[CTI] MOCK MODE enabled ip=%s", ip)
        result = _generate_mock_cti(ip)
        set_cached_cti(ip, result)
        return result

    # 4. Cooldown check
    remaining = _cooldown_remaining()
    if remaining > 0.0:
        logger.info("[CTI] Cooldown active ip=%s cooldown_remaining=%.0fs", ip, remaining)
        return {
            "verdict": "RATE_LIMITED",
            "cooldown_remaining": round(remaining),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "source": "cooldown",
        }

    # 5. Live enrichment
    try:
        result = await _enrich_live(ip)
    except Exception as exc:
        logger.error("[CTI] Unexpected enrichment failure ip=%s error=%s", ip, exc)
        return {
            "verdict": "UNKNOWN",
            "error": str(exc),
            "abuse_score": 0,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "source": "error",
        }

    # 6. Store in cache
    set_cached_cti(ip, result)
    return result
