"""
chat_engine.py — SOC Copilot (Phase 5)

Provides chat_with_ai() for querying the SOC system in natural language.

Features:
  - Fetches latest attack chain (soc-chains) + up to 5 alerts (soc-alerts)
  - Builds a structured SOC analyst prompt
  - Calls Gemini via ai_engine._call_gemini() (reuses retry + backoff logic)
  - In-memory response cache keyed by query string
  - Per-query cooldown (2 seconds between identical queries)

DO NOT modify ai_engine.py.
"""

import asyncio
import hashlib
import logging
import time
from typing import Any

from db import get_es

# Reuse Gemini's retry/backoff logic from ai_engine — DO NOT call analyze_chain()
from ai_engine import _call_gemini  # type: ignore[attr-defined]

logger = logging.getLogger("soc.chat")

# ── Index names (must match main.py) ─────────────────────────────────────────
_CHAINS_INDEX = "soc-chains"
_ALERTS_INDEX = "soc-alerts"

# ── Cache & cooldown config ───────────────────────────────────────────────────
_CACHE_TTL_SECONDS   = 300          # 5-minute TTL for cached answers
_COOLDOWN_SECONDS    = 2            # minimum gap between requests for same query
_MAX_CHAINS_CONTEXT  = 1
_MAX_ALERTS_CONTEXT  = 5

# ── In-memory stores ──────────────────────────────────────────────────────────
# { query_hash: {"response": str, "context_used": dict, "cached_at": float} }
_response_cache: dict[str, dict] = {}

# { query_hash: last_request_epoch }
_cooldown_store: dict[str, float] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _query_hash(query: str) -> str:
    """Stable short hash for a query string (used as cache + cooldown key)."""
    return hashlib.sha256(query.strip().lower().encode()).hexdigest()[:24]


def _cache_get(query_hash: str) -> dict | None:
    """Return a cached entry if it exists and hasn't expired."""
    entry = _response_cache.get(query_hash)
    if entry and (time.time() - entry["cached_at"]) < _CACHE_TTL_SECONDS:
        return entry
    if entry:
        del _response_cache[query_hash]
    return None


def _cache_set(query_hash: str, response: str, context_used: dict) -> None:
    _response_cache[query_hash] = {
        "response":     response,
        "context_used": context_used,
        "cached_at":    time.time(),
    }


def _check_cooldown(query_hash: str) -> float:
    """
    Returns 0.0 if the query is allowed, or the remaining cooldown
    in seconds if the caller must wait.
    """
    last = _cooldown_store.get(query_hash, 0.0)
    elapsed = time.time() - last
    if elapsed < _COOLDOWN_SECONDS:
        return round(_COOLDOWN_SECONDS - elapsed, 2)
    return 0.0


def _mark_cooldown(query_hash: str) -> None:
    _cooldown_store[query_hash] = time.time()


# ═══════════════════════════════════════════════════════════════════════════════
# ELASTICSEARCH CONTEXT FETCHERS
# ═══════════════════════════════════════════════════════════════════════════════

async def _fetch_latest_chain() -> dict | None:
    """Fetch the single most-recently-detected attack chain."""
    es = get_es()
    try:
        res = await es.search(
            index = _CHAINS_INDEX,
            query = {"match_all": {}},
            sort  = [{"detected_at": {"order": "desc"}}],
            size  = _MAX_CHAINS_CONTEXT,
        )
        hits = res["hits"]["hits"]
        return hits[0]["_source"] if hits else None
    except Exception as exc:
        logger.warning("[CHAT] Could not fetch chain from ES: %s", exc)
        return None


async def _fetch_latest_alerts() -> list[dict]:
    """Fetch up to 5 most recent alerts."""
    es = get_es()
    try:
        res = await es.search(
            index = _ALERTS_INDEX,
            query = {"match_all": {}},
            sort  = [{"timestamp": {"order": "desc"}}],
            size  = _MAX_ALERTS_CONTEXT,
        )
        return [h["_source"] for h in res["hits"]["hits"]]
    except Exception as exc:
        logger.warning("[CHAT] Could not fetch alerts from ES: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def _build_prompt(query: str, chain: dict | None, alerts: list[dict]) -> str:
    """
    Build a structured SOC analyst prompt that includes:
      - The user's natural-language question
      - The latest attack chain (if any)
      - The latest alerts (if any)
    """
    lines: list[str] = [
        "You are a senior SOC (Security Operations Center) analyst with deep expertise "
        "in threat detection, incident response, and MITRE ATT&CK framework.",
        "",
        "Answer the analyst's question below using ONLY the context provided. "
        "Be concise, actionable, and precise. If the context is insufficient, say so.",
        "",
        "═══════════════════════════════════════",
        "ANALYST QUESTION",
        "═══════════════════════════════════════",
        query.strip(),
        "",
    ]

    # ── Attack chain context ──────────────────────────────────────────────────
    lines += [
        "═══════════════════════════════════════",
        "LATEST ATTACK CHAIN",
        "═══════════════════════════════════════",
    ]
    if chain:
        lines += [
            f"Chain ID     : {chain.get('chain_id', 'N/A')}",
            f"Pattern      : {chain.get('pattern_name', 'N/A')}",
            f"Severity     : {chain.get('severity', 'N/A')}",
            f"Risk Score   : {chain.get('risk_score', 'N/A')}",
            f"Confidence   : {chain.get('confidence', 0) * 100:.0f}%",
            f"Detected At  : {chain.get('detected_at', 'N/A')}",
            f"Stage Seq    : {' → '.join(chain.get('stage_sequence', []))}",
            f"Attack Chain : {chain.get('attack_chain', [])}",
        ]
    else:
        lines.append("No attack chains found in the system.")

    lines.append("")

    # ── Alerts context ────────────────────────────────────────────────────────
    lines += [
        "═══════════════════════════════════════",
        f"LATEST ALERTS (up to {_MAX_ALERTS_CONTEXT})",
        "═══════════════════════════════════════",
    ]
    if alerts:
        for i, alert in enumerate(alerts, 1):
            lines += [
                f"[Alert {i}]",
                f"  Rule       : {alert.get('rule_id', 'N/A')}",
                f"  Title      : {alert.get('title', 'N/A')}",
                f"  Severity   : {alert.get('severity', 'N/A')}",
                f"  Tactic     : {alert.get('tactic', 'N/A')}",
                f"  Technique  : {alert.get('technique', 'N/A')}",
                f"  Host       : {alert.get('host', 'N/A')}",
                f"  User       : {alert.get('user', 'N/A')}",
                f"  Source IP  : {alert.get('src_ip', 'N/A')}",
                f"  Timestamp  : {alert.get('timestamp', 'N/A')}",
                f"  Description: {alert.get('description', 'N/A')}",
                "",
            ]
    else:
        lines.append("No recent alerts found in the system.")

    lines += [
        "",
        "═══════════════════════════════════════",
        "Respond as a SOC analyst. Be direct and specific.",
    ]

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

async def chat_with_ai(query: str) -> dict[str, Any]:
    """
    Main entry point for the SOC Copilot chat endpoint.

    Parameters
    ----------
    query : str
        Natural-language question from the analyst.

    Returns
    -------
    dict with keys:
        response      — Gemini's answer as a string
        context_used  — { "chains": int, "alerts": int }
        cached        — True if served from cache
        error         — Present only if something went wrong
    """
    qhash = _query_hash(query)

    # ── 1. Cache lookup ───────────────────────────────────────────────────────
    cached = _cache_get(qhash)
    if cached:
        logger.info("[CHAT] Cache hit | hash=%s", qhash)
        return {
            "response":     cached["response"],
            "context_used": cached["context_used"],
            "cached":       True,
        }

    # ── 2. Cooldown check ─────────────────────────────────────────────────────
    wait = _check_cooldown(qhash)
    if wait > 0:
        logger.info("[CHAT] Cooldown active | hash=%s wait=%.2fs", qhash, wait)
        return {
            "error":            "Too many requests for the same query.",
            "retry_after_secs": wait,
            "cached":           False,
        }

    # ── 3. Fetch ES context ───────────────────────────────────────────────────
    chain  = await _fetch_latest_chain()
    alerts = await _fetch_latest_alerts()

    context_used = {
        "chains": 1 if chain else 0,
        "alerts": len(alerts),
    }

    # ── 4. Build prompt ───────────────────────────────────────────────────────
    prompt = _build_prompt(query, chain, alerts)
    logger.debug("[CHAT] Prompt built | chars=%d chains=%d alerts=%d",
                 len(prompt), context_used["chains"], context_used["alerts"])

    # ── 5. Mark cooldown before the API call (prevents burst on slow network) ─
    _mark_cooldown(qhash)

    # ── 6. Call Gemini via ai_engine's retry-aware helper ─────────────────────
    try:
        gemini_response = _call_gemini(prompt)
    except Exception as exc:
        logger.error("[CHAT] Gemini call failed: %s", exc)
        return {
            "error":        f"Gemini API call failed: {exc!r}",
            "context_used": context_used,
            "cached":       False,
        }

    if not gemini_response:
        return {
            "error":        "Gemini returned an empty response.",
            "context_used": context_used,
            "cached":       False,
        }

    # ── 7. Cache and return ───────────────────────────────────────────────────
    _cache_set(qhash, gemini_response, context_used)
    logger.info("[CHAT] Response cached | hash=%s", qhash)

    return {
        "response":     gemini_response,
        "context_used": context_used,
        "cached":       False,
    }
