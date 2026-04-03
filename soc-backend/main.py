"""
main.py — SOC Backend Phase 5 (SOC Copilot / AI Chat)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs

Phase 2 fixes applied:
  [P2-FIX-1]  Alert deduplication via fingerprint hash before ES index
  [P2-FIX-2]  Bulk ingestion now runs detection on each item
  [P2-FIX-3]  ES index-with-retry helper (_es_index_with_retry)
  [P2-FIX-4]  Rate limiter note: still memory-based (acceptable for Phase 2/3)

Phase 3 additions:
  [P3-1]  AttackGraphEngine singleton (module-level)
  [P3-2]  Real detect() output fed into graph_engine.add_alert()
  [P3-3]  run_graph_correlation() — link + detect + store chains
  [P3-4]  soc-chains ES index with chain_id as document _id (idempotent)
  [P3-5]  GET /chains  — query stored chains
  [P3-6]  GET /graph/stats  — live graph state
  [P3-7]  POST /graph/reset — manual engine reset

Phase 4 additions:
  [P4-1]  Import analyze_chain + get_rate_limit_status from ai_engine
  [P4-2]  GET /ai/analyze — fetch chain (latest or by chain_id), run full AI pipeline
  [P4-3]  GET /ai/status  — live view of rate limiter + cache + thresholds
  [P4-FIX] /ai/analyze now accepts optional ?chain_id= query param
  [P4-FIX] GEMINI_API_KEY read from environment — set before starting server:
           export GEMINI_API_KEY=your_key_here

Phase 5 additions:
  [P5-1]  Import chat_with_ai from chat_engine
  [P5-2]  POST /chat — natural-language SOC analyst chat endpoint

Phase 5 fix:
  [P5-FIX-TIME] /alerts endpoint: "time" field now always returns HH:MM:SS.
                Falls back to current UTC time if timestamp is missing or invalid.
                Handles None, empty string, and malformed ISO strings safely.
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import asyncio
import hashlib
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert

# [P3-1] Phase 3: Attack Graph Engine
from graph_engine import AttackGraphEngine

# [P4-1] Phase 4: AI SOC Analysis
from ai_engine import analyze_chain, get_rate_limit_status

# [P5-1] Phase 5: SOC Copilot Chat
from chat_engine import chat_with_ai


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 5",
    description = "NXLog → FastAPI → Elasticsearch + Detection + Attack Graph + AI Analysis + Chat",
    version     = "8.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"
CHAINS_INDEX = "soc-chains"   # [P3-4]


# ── Phase 3 singleton ─────────────────────────────────────────────────────────
# [P3-1] One engine per process; accumulates state across requests.
# Call POST /graph/reset to start a new analysis window.
graph_engine = AttackGraphEngine(time_window_seconds=300)


# ── Rate limiter ───────────────────────────────────────────────────────────────
# [P2-FIX-4] In-memory dict. Fine for single-process Phase 5.
# Replace with Redis INCR/EXPIRE for multi-worker deployments.
_rate_limit_store: dict[str, list[float]] = {}
RATE_LIMIT_REQUESTS = 200
RATE_LIMIT_WINDOW   = 60


def _check_rate_limit(client_ip: str) -> bool:
    now  = time.time()
    hits = [t for t in _rate_limit_store.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
    if len(hits) >= RATE_LIMIT_REQUESTS:
        _rate_limit_store[client_ip] = hits
        return False
    hits.append(now)
    _rate_limit_store[client_ip] = hits
    return True


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _is_nxlog(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return "nxlog" in ua


# ── Doc prep ───────────────────────────────────────────────────────────────────
def _prep_doc(log) -> dict:
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Body parser ────────────────────────────────────────────────────────────────
def _parse_body(content_type: str, raw_body: bytes) -> tuple[str, dict]:
    body_str = raw_body.decode("utf-8", errors="replace").strip()
    is_json  = "json" in content_type.lower() or body_str.startswith("{")
    if is_json:
        try:
            data = json.loads(body_str)
            if "payload" in data:
                return data.get("source", "nxlog"), data.get("payload", {})
            return "nxlog", data
        except json.JSONDecodeError:
            logger.warning("[PARSE] JSON parse failed, falling back to syslog parser")
    return "nxlog", _parse_syslog_string(body_str)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSLOG PARSER
# ═══════════════════════════════════════════════════════════════════════════════
_RE_KV             = re.compile(r'([\w\-]+)="([^"]*)"')
_RE_EVENTID        = re.compile(r'\bEventID=(\d+)', re.IGNORECASE)
_RE_IPV4           = re.compile(
    r'^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$'
)
_RE_SERVICE_PRINCIPAL = re.compile(
    r'^(nt authority|window manager|font driver host)\\', re.IGNORECASE
)
_SKIP_USERS: frozenset[str] = frozenset({
    "-", "", "system", "local service", "network service",
    "anonymous logon", "iis apppool", "dwm-1", "umfd-0", "umfd-1",
})
_SKIP_IPS: frozenset[str] = frozenset({
    "-", "", "::1", "::ffff:127.0.0.1", "127.0.0.1", "0.0.0.0", "fe80::1",
})
_USER_FIELDS  = ("TargetUserName", "SubjectUserName", "AccountName", "UserName")
_IP_FIELDS    = ("IpAddress", "SourceAddress", "SourceNetworkAddress")
_PROC_FIELDS  = ("NewProcessName", "ProcessName", "Application")


def _parse_syslog_string(raw: str) -> dict:
    payload: dict = {"raw_message": raw}
    try:
        kv: dict[str, str] = dict(_RE_KV.findall(raw))
        payload["_kv"] = kv

        event_id = kv.get("EventID", "").strip()
        if not event_id:
            m = _RE_EVENTID.search(raw)
            if m:
                event_id = m.group(1)
        if event_id:
            payload["EventID"] = event_id

        hostname = (kv.get("Hostname") or kv.get("Computer") or "").strip()
        if not hostname:
            parts = raw.split()
            if len(parts) >= 4 and parts[3] not in ("-", ""):
                hostname = parts[3]
        if hostname:
            payload["Hostname"] = hostname

        for field in _USER_FIELDS:
            v = kv.get(field, "").strip()
            if not v:
                continue
            if v.endswith("$"):
                continue
            if _RE_SERVICE_PRINCIPAL.match(v):
                continue
            if v.lower() in _SKIP_USERS:
                continue
            payload["TargetUserName"] = v
            break

        for field in _IP_FIELDS:
            v = kv.get(field, "").strip()
            if not v or v in _SKIP_IPS:
                continue
            if _RE_IPV4.match(v):
                payload["IpAddress"] = v
                break
            if len(v) > 4:
                payload["IpAddress"] = v
                break

        for field in _PROC_FIELDS:
            v = kv.get(field, "").strip()
            if v and v != "-":
                payload["ProcessName"] = v
                break

        cmdline = kv.get("CommandLine", "").strip()
        if not cmdline:
            m = re.search(r'CommandLine="([^"]*)"', raw)
            if m:
                cmdline = m.group(1)
        if cmdline:
            payload["CommandLine"] = cmdline

        logon_raw = (kv.get("LogonType") or kv.get("Logon-Type") or "").strip()
        if logon_raw:
            payload["LogonType"] = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw

    except Exception as exc:
        logger.error(f"[PARSE SYSLOG] Error: {exc!r} | raw[:200]={raw[:200]!r}")

    logger.info(
        f"[PARSE SYSLOG] EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')} proc={payload.get('ProcessName')} "
        f"cmdline={'yes' if payload.get('CommandLine') else 'no'} "
        f"logon_type={payload.get('LogonType')}"
    )
    return payload


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR EVENT BUILDER
# ═══════════════════════════════════════════════════════════════════════════════
def _build_detector_event(doc: dict, payload: dict) -> dict:
    event_id = str(
        payload.get("EventID") or doc.get("event_id") or ""
    ).strip()
    user = str(
        payload.get("TargetUserName") or doc.get("user") or ""
    ).strip()
    host = str(
        payload.get("Hostname") or doc.get("host") or "unknown"
    ).strip().lower()
    if not host or host in ("-", ""):
        host = "unknown"
    src_ip = str(
        payload.get("IpAddress") or doc.get("src_ip") or ""
    ).strip()
    if src_ip in ("-", "::1", "127.0.0.1"):
        src_ip = ""
    process = str(
        payload.get("ProcessName") or doc.get("process") or ""
    ).strip()
    cmdline = str(payload.get("CommandLine") or "").strip()
    logon_raw = str(
        payload.get("LogonType") or doc.get("logon_type") or ""
    ).strip()
    logon_type  = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw
    raw_message = payload.get("raw_message", "")

    return {
        "event_id":       event_id,
        "EventID":        event_id,
        "user":           user,
        "TargetUserName": user,
        "host":           host,
        "Hostname":       host,
        "src_ip":         src_ip,
        "IpAddress":      src_ip,
        "process":        process,
        "ProcessName":    process,
        "logon_type":     logon_type,
        "LogonType":      logon_type,
        "cmdline":        cmdline,
        "CommandLine":    cmdline,
        "raw_message":    raw_message,
        **{k: v for k, v in doc.items() if k not in (
            "event_id", "user", "host", "src_ip", "process", "logon_type"
        )},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ES HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def _es_index_with_retry(
    index: str,
    document: dict,
    doc_id: Optional[str] = None,
    retries: int = 1,
) -> bool:
    es = get_es()
    for attempt in range(retries + 1):
        try:
            if doc_id:
                await es.index(index=index, id=doc_id, document=document)
            else:
                await es.index(index=index, document=document)
            return True
        except Exception as exc:
            if attempt < retries:
                logger.warning(
                    "[ES RETRY] attempt=%d index=%s error=%s", attempt + 1, index, exc
                )
                await asyncio.sleep(0.3 * (attempt + 1))
            else:
                logger.error("[ES FAIL] index=%s doc_id=%s error=%s", index, doc_id, exc)
    return False


def _alert_fingerprint(alert: Alert) -> str:
    raw = f"{alert.rule_id}|{alert.host}|{alert.user}|{alert.timestamp[:16]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


async def _ensure_alerts_index() -> None:
    es = get_es()
    try:
        if not await es.indices.exists(index=ALERTS_INDEX):
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp":    {"type": "date"},
                        "severity":     {"type": "keyword"},
                        "rule_id":      {"type": "keyword"},
                        "technique":    {"type": "keyword"},
                        "tactic":       {"type": "keyword"},
                        "host":         {"type": "keyword"},
                        "user":         {"type": "keyword"},
                        "src_ip":       {"type": "ip", "ignore_malformed": True},
                        "title":        {"type": "text"},
                        "description":  {"type": "text"},
                        "fingerprint":  {"type": "keyword"},
                    }
                }
            )
    except Exception as e:
        logger.error("[ALERTS INDEX] Could not create: %s", e)


async def _ensure_chains_index() -> None:
    es = get_es()
    try:
        if not await es.indices.exists(index=CHAINS_INDEX):
            await es.indices.create(
                index    = CHAINS_INDEX,
                mappings = {
                    "properties": {
                        "chain_id":       {"type": "keyword"},
                        "pattern_name":   {"type": "keyword"},
                        "severity":       {"type": "keyword"},
                        "risk_score":     {"type": "integer"},
                        "confidence":     {"type": "float"},
                        "stage_sequence": {"type": "keyword"},
                        "detected_at":    {"type": "date"},
                        "attack_chain":   {"type": "keyword"},
                    }
                }
            )
    except Exception as e:
        logger.error("[CHAINS INDEX] Could not create: %s", e)


async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    await _ensure_alerts_index()
    for alert in alerts:
        fp  = _alert_fingerprint(alert)
        doc = alert.to_dict()
        doc["fingerprint"] = fp
        ok  = await _es_index_with_retry(ALERTS_INDEX, doc, doc_id=fp)
        if ok:
            logger.info(
                "[ALERT STORED] rule=%-15s severity=%-8s host=%s fp=%s",
                alert.rule_id, alert.severity, alert.host, fp,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: GRAPH CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════
async def _run_graph_correlation() -> list[dict]:
    graph_engine.link_events()
    chains = graph_engine.detect_attack_chain()
    if chains:
        await _ensure_chains_index()
        for chain in chains:
            stored = await _es_index_with_retry(
                CHAINS_INDEX,
                chain,
                doc_id=chain["chain_id"],
            )
            if stored:
                logger.warning(
                    "[CHAIN STORED] pattern='%s' chain_id=%s "
                    "risk=%d severity=%s confidence=%.0f%% stages=%s",
                    chain["pattern_name"], chain["chain_id"],
                    chain["risk_score"], chain["severity"],
                    chain["confidence"] * 100,
                    " → ".join(chain["stage_sequence"]),
                )
    summary = graph_engine.graph_summary()
    logger.info(
        "[GRAPH STATE] nodes=%d edges=%d components=%d seen_chains=%d",
        summary["nodes"], summary["edges"],
        summary.get("components", 0), summary.get("chains_detected", 0),
    )
    return chains


# ═══════════════════════════════════════════════════════════════════════════════
# INGESTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")
    source, payload = _parse_body(content_type, raw_body)

    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Normalization failed: {exc}")

    doc = _prep_doc(normalized)
    await _es_index_with_retry(get_index(), doc, doc_id=normalized.id)

    event_for_detector = _build_detector_event(doc, payload)
    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        for alert in alerts:
            graph_engine.add_alert(alert.to_dict())
        await _run_graph_correlation()

    return {
        "id":       normalized.id,
        "alerts":   len(alerts),
        "is_nxlog": _is_nxlog(request),
    }


@app.post("/logs/bulk", response_model=BulkIngestionResponse, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    try:
        items = json.loads(raw_body.decode("utf-8", errors="replace"))
        if not isinstance(items, list):
            items = [items]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON array: {exc}")

    accepted_ids:  list[str]   = []
    errors:        list[str]   = []
    bulk_ops:      list        = []
    all_alerts:    list[Alert] = []
    total_chains:  int         = 0

    for i, item in enumerate(items):
        try:
            if "payload" in item:
                source  = item.get("source", "nxlog")
                payload = item.get("payload", {})
            else:
                source, payload = "nxlog", item

            normalized = normalize(LogSource(source), payload)
            doc        = _prep_doc(normalized)
            bulk_ops.append({"index": {"_index": get_index(), "_id": normalized.id}})
            bulk_ops.append(doc)
            accepted_ids.append(normalized.id)

            event_for_detector = _build_detector_event(doc, payload)
            try:
                item_alerts = detect(event_for_detector)
            except Exception as det_err:
                logger.error("[BULK DETECT] item=%d error=%r", i, det_err)
                item_alerts = []

            all_alerts.extend(item_alerts)
            for alert in item_alerts:
                graph_engine.add_alert(alert.to_dict())

        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

    if all_alerts:
        await _index_alerts(all_alerts)

    if all_alerts:
        chains       = await _run_graph_correlation()
        total_chains = len(chains)
        logger.warning(
            "[BULK] items=%d accepted=%d alerts=%d chains=%d errors=%d",
            len(items), len(accepted_ids), len(all_alerts),
            total_chains, len(errors),
        )

    return BulkIngestionResponse(
        success  = len(errors) == 0,
        accepted = len(accepted_ids),
        rejected = len(errors),
        log_ids  = accepted_ids,
        errors   = errors,
    )


# ── GET /logs ──────────────────────────────────────────────────────────────────
@app.get("/logs", response_model=list[LogResponse], tags=["Query"])
async def get_logs(
    event_type: Optional[EventType] = Query(None),
    user:       Optional[str]       = Query(None),
    host:       Optional[str]       = Query(None),
    process:    Optional[str]       = Query(None),
    since:      Optional[datetime]  = Query(None),
    limit:      int                 = Query(100, le=1000),
):
    must = []
    if event_type: must.append({"term":     {"event_type": event_type.value}})
    if user:       must.append({"wildcard": {"user":            {"value": f"*{user}*",    "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":            {"value": f"*{host}*",    "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*", "case_insensitive": True}}})
    if since:      must.append({"range":    {"timestamp":       {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    res   = await es.search(
        index = get_index(),
        query = query,
        sort  = [{"timestamp": {"order": "desc"}}],
        size  = limit,
    )
    return [LogResponse(**hit["_source"]) for hit in res["hits"]["hits"]]


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────
@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── GET /alerts ────────────────────────────────────────────────────────────────
@app.get("/alerts", tags=["Detection"])
async def get_alerts(
    severity:  Optional[str]      = Query(None, description="critical|high|medium|low"),
    tactic:    Optional[str]      = Query(None),
    host:      Optional[str]      = Query(None),
    rule_id:   Optional[str]      = Query(None),
    since:     Optional[datetime] = Query(None),
    limit:     int                = Query(50, le=500),
):
    must = []
    if severity: must.append({"term":     {"severity": severity}})
    if tactic:   must.append({"wildcard": {"tactic":   {"value": f"*{tactic}*", "case_insensitive": True}}})
    if host:     must.append({"wildcard": {"host":     {"value": f"*{host}*",   "case_insensitive": True}}})
    if rule_id:  must.append({"term":     {"rule_id":  rule_id}})
    if since:    must.append({"range":    {"timestamp": {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    try:
        res = await es.search(
            index = ALERTS_INDEX,
            query = query,
            sort  = [{"timestamp": {"order": "desc"}}],
            size  = limit,
        )
    except Exception:
        return []

    alerts = []
    for hit in res["hits"]["hits"]:
        alert = hit["_source"].copy()

        # [P5-FIX-TIME] Robustly extract HH:MM:SS from timestamp.
        # Covers: valid ISO strings, Z-suffix variants, missing keys,
        # None values, empty strings, and completely malformed timestamps.
        # Falls back to current UTC time so "time" is NEVER null or empty.
        raw_ts = alert.get("timestamp") or ""
        try:
            parsed_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            parsed_ts = datetime.now(timezone.utc)
            logger.warning(
                "[ALERTS] Invalid or missing timestamp %r for alert rule=%s host=%s — "
                "using current UTC time as fallback.",
                raw_ts,
                alert.get("rule_id", "unknown"),
                alert.get("host", "unknown"),
            )
        alert["time"] = parsed_ts.strftime("%H:%M:%S")

        alerts.append(alert)

    return alerts


# ── GET /alerts/summary ────────────────────────────────────────────────────────
@app.get("/alerts/summary", tags=["Detection"])
async def alerts_summary():
    es = get_es()
    try:
        res = await es.search(
            index = ALERTS_INDEX,
            size  = 0,
            aggs  = {
                "by_severity": {"terms": {"field": "severity", "size": 5}},
                "by_tactic":   {"terms": {"field": "tactic",   "size": 10}},
                "by_rule":     {"terms": {"field": "rule_id",  "size": 20}},
                "by_host":     {"terms": {"field": "host",     "size": 10}},
                "timeline":    {
                    "date_histogram": {
                        "field":             "timestamp",
                        "calendar_interval": "hour",
                    }
                },
            },
        )
    except Exception:
        return {"total": 0, "by_severity": {}, "by_tactic": {},
                "by_rule": {}, "by_host": {}, "timeline": []}

    aggs = res["aggregations"]
    return {
        "total":       res["hits"]["total"]["value"],
        "by_severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
        "by_tactic":   {b["key"]: b["doc_count"] for b in aggs["by_tactic"]["buckets"]},
        "by_rule":     {b["key"]: b["doc_count"] for b in aggs["by_rule"]["buckets"]},
        "by_host":     {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]},
        "timeline":    [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
        ],
    }


# ── GET /logs/stats/summary ────────────────────────────────────────────────────
@app.get("/logs/stats/summary", tags=["Analytics"])
async def log_summary():
    es  = get_es()
    res = await es.search(
        index = get_index(),
        size  = 0,
        aggs  = {
            "by_type":  {"terms": {"field": "event_type", "size": 20}},
            "by_host":  {"terms": {"field": "host",       "size": 10}},
            "timeline": {
                "date_histogram": {
                    "field":             "timestamp",
                    "calendar_interval": "hour",
                }
            },
            "avg_latency_ms": {
                "avg": {
                    "script": {
                        "source": (
                            "doc['ingested_at'].value.toInstant().toEpochMilli() "
                            "- doc['timestamp'].value.toInstant().toEpochMilli()"
                        )
                    }
                }
            },
        },
    )
    aggs = res["aggregations"]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]},
        "by_host":        {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]},
        "timeline":       [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
        ],
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /chains ────────────────────────────────────────────────────────────────
@app.get("/chains", tags=["Attack Graph"])
async def get_chains(
    severity:     Optional[str]      = Query(None, description="critical|high|medium|low"),
    pattern_name: Optional[str]      = Query(None),
    since:        Optional[datetime] = Query(None),
    limit:        int                = Query(20, le=200),
):
    must = []
    if severity:     must.append({"term":     {"severity":     severity}})
    if pattern_name: must.append({"wildcard": {"pattern_name": {"value": f"*{pattern_name}*", "case_insensitive": True}}})
    if since:        must.append({"range":    {"detected_at":  {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    try:
        res = await es.search(
            index = CHAINS_INDEX,
            query = query,
            sort  = [{"detected_at": {"order": "desc"}}],
            size  = limit,
        )
    except Exception:
        return {"total": 0, "chains": []}

    hits = [h["_source"] for h in res["hits"]["hits"]]
    return {"total": len(hits), "chains": hits}


# ── GET /graph/stats ──────────────────────────────────────────────────────────
@app.get("/graph/stats", tags=["Attack Graph"])
async def graph_stats():
    return {
        "engine":    "AttackGraphEngine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **graph_engine.graph_summary(),
    }


# ── POST /graph/reset ─────────────────────────────────────────────────────────
@app.post("/graph/reset", tags=["Attack Graph"])
async def reset_graph():
    graph_engine.reset()
    return {
        "success":   True,
        "message":   "Graph engine state cleared",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── GET /ai/analyze ───────────────────────────────────────────────────────────
# [P4-2] Fetch chain (latest or by chain_id) → hard rate limiter → cache → Gemini
@app.get("/ai/analyze", tags=["AI Analysis"])
async def ai_analyze_chain(
    chain_id: Optional[str] = Query(
        None,
        description=(
            "Specific chain_id to analyze. "
            "Omit to analyze the most recently detected chain."
        ),
    )
):
    """
    Fetch an attack chain from soc-chains and analyze it using Google Gemini
    acting as a senior SOC analyst.

    - Pass **?chain_id=<id>** to analyze a specific chain.
    - Omit the parameter to analyze the most recently detected chain.

    Pipeline in ai_engine.py:
      1. Smart trigger guard  — skips chains with risk_score < 50
      2. Cache lookup         — returns instantly if chain seen before (1h TTL)
      3. Hard rate limiter    — rejects if 15 RPM / 1500 RPD quota is full
      4. Gemini API call      — proper backoff on 429 (15s → 30s → 60s)
      5. Cache store          — saves result for future identical chains

    Returns:
        { "chain": <chain>, "analysis": <structured AI text>, "ai_status": <quota info> }
    """
    es = get_es()

    # ── Fetch chain from ES ───────────────────────────────────────────────
    try:
        if chain_id:
            try:
                res   = await es.get(index=CHAINS_INDEX, id=chain_id)
                chain = res["_source"]
            except Exception:
                raise HTTPException(
                    status_code=404,
                    detail=f"Chain '{chain_id}' not found in soc-chains index.",
                )
        else:
            res = await es.search(
                index = CHAINS_INDEX,
                query = {"match_all": {}},
                sort  = [{"detected_at": {"order": "desc"}}],
                size  = 1,
            )
            hits = res["hits"]["hits"]
            if not hits:
                return JSONResponse(
                    status_code=404,
                    content={
                        "error":     "No attack chains found in soc-chains index.",
                        "hint":      "Ingest logs first to generate chains via POST /logs",
                        "chain":     None,
                        "analysis":  None,
                        "ai_status": get_rate_limit_status(),
                    },
                )
            chain = hits[0]["_source"]

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[AI ANALYZE] Elasticsearch query failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch unavailable — cannot fetch attack chains.",
        )

    # ── Run full AI pipeline (rate limit + cache + Gemini) ────────────────
    try:
        analysis = analyze_chain(chain)
    except Exception as exc:
        logger.exception("[AI ANALYZE] Unexpected error from analyze_chain")
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed unexpectedly: {exc!r}",
        )

    logger.info(
        "[AI ANALYZE] Done | chain_id=%s pattern=%s",
        chain.get("chain_id", "N/A"),
        chain.get("pattern_name", "N/A"),
    )

    return {
        "chain":     chain,
        "analysis":  analysis,
        "ai_status": get_rate_limit_status(),
    }


# ── GET /ai/status ────────────────────────────────────────────────────────────
# [P4-3] Live view of Gemini quota usage, cache state, and thresholds
@app.get("/ai/status", tags=["AI Analysis"])
async def ai_status():
    """
    Returns live Gemini rate limiter usage, cache stats, and configured thresholds.
    Use this to monitor quota consumption before hitting /ai/analyze.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **get_rate_limit_status(),
    }


# ── POST /chat ─────────────────────────────────────────────────────────────────
# [P5-2] SOC Copilot — natural-language chat over live SOC context
@app.post("/chat", tags=["SOC Copilot"])
async def chat_endpoint(body: dict):
    """
    Ask the SOC Copilot anything about your current threat landscape.

    The system automatically pulls the latest attack chain and up to 5 recent
    alerts from Elasticsearch, builds a structured analyst prompt, and queries
    Gemini for a focused, actionable response.

    Request body:
        { "query": "Are there any lateral movement indicators?" }

    Response:
        {
          "response":     "<Gemini answer>",
          "context_used": { "chains": 1, "alerts": 5 },
          "cached":       false
        }

    Errors:
        { "error": "Query is required" }
        { "error": "Too many requests...", "retry_after_secs": 1.8 }
    """
    query = body.get("query")

    if not query:
        return {"error": "Query is required"}

    return await chat_with_ai(query)


# ── Debug / Admin ──────────────────────────────────────────────────────────────
@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    logger.info(f"[DEBUG RAW] ct={request.headers.get('content-type')} ua={request.headers.get('user-agent')}")
    logger.info(f"[DEBUG RAW] body={json.dumps(parsed, default=str)[:500]}")
    return {"received": parsed, "size_bytes": len(body)}


@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    await reset_index()
    return {"success": True, "message": "soc-logs index recreated"}


@app.post("/admin/reset-alerts", tags=["Admin"])
async def admin_reset_alerts():
    es = get_es()
    try:
        await es.indices.delete(index=ALERTS_INDEX)
    except Exception:
        pass
    return {"success": True, "message": "soc-alerts index deleted"}


@app.post("/admin/reset-chains", tags=["Admin"])
async def admin_reset_chains():
    es = get_es()
    try:
        await es.indices.delete(index=CHAINS_INDEX)
    except Exception:
        pass
    graph_engine.reset()
    return {"success": True, "message": "soc-chains index deleted and graph engine reset"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 5 (SOC Copilot / AI Chat)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs

Phase 2 fixes applied:
  [P2-FIX-1]  Alert deduplication via fingerprint hash before ES index
  [P2-FIX-2]  Bulk ingestion now runs detection on each item
  [P2-FIX-3]  ES index-with-retry helper (_es_index_with_retry)
  [P2-FIX-4]  Rate limiter note: still memory-based (acceptable for Phase 2/3)

Phase 3 additions:
  [P3-1]  AttackGraphEngine singleton (module-level)
  [P3-2]  Real detect() output fed into graph_engine.add_alert()
  [P3-3]  run_graph_correlation() — link + detect + store chains
  [P3-4]  soc-chains ES index with chain_id as document _id (idempotent)
  [P3-5]  GET /chains  — query stored chains
  [P3-6]  GET /graph/stats  — live graph state
  [P3-7]  POST /graph/reset — manual engine reset

Phase 4 additions:
  [P4-1]  Import analyze_chain + get_rate_limit_status from ai_engine
  [P4-2]  GET /ai/analyze — fetch chain (latest or by chain_id), run full AI pipeline
  [P4-3]  GET /ai/status  — live view of rate limiter + cache + thresholds
  [P4-FIX] /ai/analyze now accepts optional ?chain_id= query param
  [P4-FIX] GEMINI_API_KEY read from environment — set before starting server:
           export GEMINI_API_KEY=your_key_here

Phase 5 additions:
  [P5-1]  Import chat_with_ai from chat_engine
  [P5-2]  POST /chat — natural-language SOC analyst chat endpoint

Phase 5 fixes:
  [P5-FIX-TIME]      /alerts: "time" field always returns HH:MM:SS, never null/empty.
                     Falls back to current UTC time if timestamp is missing or invalid.

  [P5-FIX-RATELIMIT] 429 Too Many Requests from NXLog eliminated permanently.
                     Three-tier rate limit strategy:
                       Tier 0 — Private/loopback IPs (RFC-1918 + ::1) → UNLIMITED
                                192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x
                       Tier 1 — NXLog user-agent detected              → 2000 req/60s
                       Tier 2 — All other external clients             → 300 req/60s
                     NXLog agents running on the same LAN are trusted internal
                     infrastructure and must never be rate-limited.
                     Adjust RATE_LIMIT_* constants below to tune per environment.
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import asyncio
import hashlib
import ipaddress
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert

# [P3-1] Phase 3: Attack Graph Engine
from graph_engine import AttackGraphEngine

# [P4-1] Phase 4: AI SOC Analysis
from ai_engine import analyze_chain, get_rate_limit_status

# [P5-1] Phase 5: SOC Copilot Chat
from chat_engine import chat_with_ai


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 5",
    description = "NXLog → FastAPI → Elasticsearch + Detection + Attack Graph + AI Analysis + Chat",
    version     = "8.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"
CHAINS_INDEX = "soc-chains"


# ── Phase 3 singleton ─────────────────────────────────────────────────────────
# [P3-1] One engine per process; accumulates state across requests.
# Call POST /graph/reset to start a new analysis window.
graph_engine = AttackGraphEngine(time_window_seconds=300)


# ═══════════════════════════════════════════════════════════════════════════════
# [P5-FIX-RATELIMIT] THREE-TIER RATE LIMITER
#
# Root cause of 429s: NXLog ships logs from 192.168.x.x at high frequency.
# The old single-tier limiter (200 req/60s) treated it the same as a browser
# client and choked it immediately.
#
# Fix — three tiers evaluated in order:
#
#   Tier 0  RFC-1918 private + loopback ranges → ALWAYS ALLOWED, no counter.
#           Covers: 10/8, 172.16/12, 192.168/16, 127/8, ::1, fc00/7 (IPv6 ULA)
#           This is the primary fix. NXLog on your LAN (192.168.241.128) will
#           NEVER hit a rate limit again regardless of how fast it ships logs.
#
#   Tier 1  Non-private IP with NXLog user-agent → 2000 req / 60 s
#           Safety net for NXLog agents routed through a NAT/proxy where the
#           source IP appears public. High enough that aggressive batching is
#           fine; low enough to stop a runaway shipper.
#
#   Tier 2  All other external clients (browsers, curl, etc.) → 300 req / 60 s
#           Slightly higher than original 200 to absorb dashboard polling bursts.
#
# To tune: change the four RATE_LIMIT_* constants below.
# For multi-worker deployments replace _rate_limit_store with Redis INCR/EXPIRE.
# ═══════════════════════════════════════════════════════════════════════════════

# Tier 1 — NXLog / trusted log-shipper agents (non-private IP)
RATE_LIMIT_NXLOG_REQUESTS   = 2000
RATE_LIMIT_NXLOG_WINDOW     = 60    # seconds

# Tier 2 — Generic external clients
RATE_LIMIT_DEFAULT_REQUESTS = 300
RATE_LIMIT_DEFAULT_WINDOW   = 60    # seconds

# Sliding-window store  { "ip": [hit_epoch, ...] }
_rate_limit_store: dict[str, list[float]] = {}

# Private / loopback networks — Tier 0 (bypass all rate limiting)
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),   # IPv6 ULA
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True when ip_str is a loopback or RFC-1918 private address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # Unparseable string (hostname, empty, etc.) — do not whitelist
        return False


def _check_rate_limit(client_ip: str, is_nxlog_client: bool) -> bool:
    """
    Three-tier rate limiter. Returns True = allow, False = reject (429).

    Tier 0: private/loopback  → always True  (no counter touched)
    Tier 1: NXLog user-agent  → 2000 / 60 s
    Tier 2: everyone else     → 300  / 60 s
    """
    # ── Tier 0 ───────────────────────────────────────────────────────────
    if _is_private_ip(client_ip):
        return True

    # ── Tier 1 / 2: sliding-window counter ───────────────────────────────
    max_req     = RATE_LIMIT_NXLOG_REQUESTS   if is_nxlog_client else RATE_LIMIT_DEFAULT_REQUESTS
    window_secs = RATE_LIMIT_NXLOG_WINDOW     if is_nxlog_client else RATE_LIMIT_DEFAULT_WINDOW

    now  = time.time()
    hits = [t for t in _rate_limit_store.get(client_ip, []) if now - t < window_secs]

    if len(hits) >= max_req:
        _rate_limit_store[client_ip] = hits   # persist pruned list without new hit
        logger.warning(
            "[RATE LIMIT] BLOCKED ip=%s tier=%s hits=%d limit=%d window=%ds",
            client_ip,
            "nxlog" if is_nxlog_client else "default",
            len(hits), max_req, window_secs,
        )
        return False

    hits.append(now)
    _rate_limit_store[client_ip] = hits
    return True


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _is_nxlog(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return "nxlog" in ua


# ── Doc prep ───────────────────────────────────────────────────────────────────
def _prep_doc(log) -> dict:
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Body parser ────────────────────────────────────────────────────────────────
def _parse_body(content_type: str, raw_body: bytes) -> tuple[str, dict]:
    body_str = raw_body.decode("utf-8", errors="replace").strip()
    is_json  = "json" in content_type.lower() or body_str.startswith("{")
    if is_json:
        try:
            data = json.loads(body_str)
            if "payload" in data:
                return data.get("source", "nxlog"), data.get("payload", {})
            return "nxlog", data
        except json.JSONDecodeError:
            logger.warning("[PARSE] JSON parse failed, falling back to syslog parser")
    return "nxlog", _parse_syslog_string(body_str)


# ═══════════════════════════════════════════════════════════════════════════════
# SYSLOG PARSER
# ═══════════════════════════════════════════════════════════════════════════════
_RE_KV             = re.compile(r'([\w\-]+)="([^"]*)"')
_RE_EVENTID        = re.compile(r'\bEventID=(\d+)', re.IGNORECASE)
_RE_IPV4           = re.compile(
    r'^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$'
)
_RE_SERVICE_PRINCIPAL = re.compile(
    r'^(nt authority|window manager|font driver host)\\', re.IGNORECASE
)
_SKIP_USERS: frozenset[str] = frozenset({
    "-", "", "system", "local service", "network service",
    "anonymous logon", "iis apppool", "dwm-1", "umfd-0", "umfd-1",
})
_SKIP_IPS: frozenset[str] = frozenset({
    "-", "", "::1", "::ffff:127.0.0.1", "127.0.0.1", "0.0.0.0", "fe80::1",
})
_USER_FIELDS  = ("TargetUserName", "SubjectUserName", "AccountName", "UserName")
_IP_FIELDS    = ("IpAddress", "SourceAddress", "SourceNetworkAddress")
_PROC_FIELDS  = ("NewProcessName", "ProcessName", "Application")


def _parse_syslog_string(raw: str) -> dict:
    payload: dict = {"raw_message": raw}
    try:
        kv: dict[str, str] = dict(_RE_KV.findall(raw))
        payload["_kv"] = kv

        event_id = kv.get("EventID", "").strip()
        if not event_id:
            m = _RE_EVENTID.search(raw)
            if m:
                event_id = m.group(1)
        if event_id:
            payload["EventID"] = event_id

        hostname = (kv.get("Hostname") or kv.get("Computer") or "").strip()
        if not hostname:
            parts = raw.split()
            if len(parts) >= 4 and parts[3] not in ("-", ""):
                hostname = parts[3]
        if hostname:
            payload["Hostname"] = hostname

        for field in _USER_FIELDS:
            v = kv.get(field, "").strip()
            if not v:
                continue
            if v.endswith("$"):
                continue
            if _RE_SERVICE_PRINCIPAL.match(v):
                continue
            if v.lower() in _SKIP_USERS:
                continue
            payload["TargetUserName"] = v
            break

        for field in _IP_FIELDS:
            v = kv.get(field, "").strip()
            if not v or v in _SKIP_IPS:
                continue
            if _RE_IPV4.match(v):
                payload["IpAddress"] = v
                break
            if len(v) > 4:
                payload["IpAddress"] = v
                break

        for field in _PROC_FIELDS:
            v = kv.get(field, "").strip()
            if v and v != "-":
                payload["ProcessName"] = v
                break

        cmdline = kv.get("CommandLine", "").strip()
        if not cmdline:
            m = re.search(r'CommandLine="([^"]*)"', raw)
            if m:
                cmdline = m.group(1)
        if cmdline:
            payload["CommandLine"] = cmdline

        logon_raw = (kv.get("LogonType") or kv.get("Logon-Type") or "").strip()
        if logon_raw:
            payload["LogonType"] = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw

    except Exception as exc:
        logger.error(f"[PARSE SYSLOG] Error: {exc!r} | raw[:200]={raw[:200]!r}")

    logger.info(
        f"[PARSE SYSLOG] EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')} proc={payload.get('ProcessName')} "
        f"cmdline={'yes' if payload.get('CommandLine') else 'no'} "
        f"logon_type={payload.get('LogonType')}"
    )
    return payload


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR EVENT BUILDER
# ═══════════════════════════════════════════════════════════════════════════════
def _build_detector_event(doc: dict, payload: dict) -> dict:
    event_id = str(
        payload.get("EventID") or doc.get("event_id") or ""
    ).strip()
    user = str(
        payload.get("TargetUserName") or doc.get("user") or ""
    ).strip()
    host = str(
        payload.get("Hostname") or doc.get("host") or "unknown"
    ).strip().lower()
    if not host or host in ("-", ""):
        host = "unknown"
    src_ip = str(
        payload.get("IpAddress") or doc.get("src_ip") or ""
    ).strip()
    if src_ip in ("-", "::1", "127.0.0.1"):
        src_ip = ""
    process = str(
        payload.get("ProcessName") or doc.get("process") or ""
    ).strip()
    cmdline = str(payload.get("CommandLine") or "").strip()
    logon_raw = str(
        payload.get("LogonType") or doc.get("logon_type") or ""
    ).strip()
    logon_type  = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw
    raw_message = payload.get("raw_message", "")

    return {
        "event_id":       event_id,
        "EventID":        event_id,
        "user":           user,
        "TargetUserName": user,
        "host":           host,
        "Hostname":       host,
        "src_ip":         src_ip,
        "IpAddress":      src_ip,
        "process":        process,
        "ProcessName":    process,
        "logon_type":     logon_type,
        "LogonType":      logon_type,
        "cmdline":        cmdline,
        "CommandLine":    cmdline,
        "raw_message":    raw_message,
        **{k: v for k, v in doc.items() if k not in (
            "event_id", "user", "host", "src_ip", "process", "logon_type"
        )},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ES HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
async def _es_index_with_retry(
    index: str,
    document: dict,
    doc_id: Optional[str] = None,
    retries: int = 1,
) -> bool:
    es = get_es()
    for attempt in range(retries + 1):
        try:
            if doc_id:
                await es.index(index=index, id=doc_id, document=document)
            else:
                await es.index(index=index, document=document)
            return True
        except Exception as exc:
            if attempt < retries:
                logger.warning(
                    "[ES RETRY] attempt=%d index=%s error=%s", attempt + 1, index, exc
                )
                await asyncio.sleep(0.3 * (attempt + 1))
            else:
                logger.error("[ES FAIL] index=%s doc_id=%s error=%s", index, doc_id, exc)
    return False


def _alert_fingerprint(alert: Alert) -> str:
    raw = f"{alert.rule_id}|{alert.host}|{alert.user}|{alert.timestamp[:16]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


async def _ensure_alerts_index() -> None:
    es = get_es()
    try:
        if not await es.indices.exists(index=ALERTS_INDEX):
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp":    {"type": "date"},
                        "severity":     {"type": "keyword"},
                        "rule_id":      {"type": "keyword"},
                        "technique":    {"type": "keyword"},
                        "tactic":       {"type": "keyword"},
                        "host":         {"type": "keyword"},
                        "user":         {"type": "keyword"},
                        "src_ip":       {"type": "ip", "ignore_malformed": True},
                        "title":        {"type": "text"},
                        "description":  {"type": "text"},
                        "fingerprint":  {"type": "keyword"},
                    }
                }
            )
    except Exception as e:
        logger.error("[ALERTS INDEX] Could not create: %s", e)


async def _ensure_chains_index() -> None:
    es = get_es()
    try:
        if not await es.indices.exists(index=CHAINS_INDEX):
            await es.indices.create(
                index    = CHAINS_INDEX,
                mappings = {
                    "properties": {
                        "chain_id":       {"type": "keyword"},
                        "pattern_name":   {"type": "keyword"},
                        "severity":       {"type": "keyword"},
                        "risk_score":     {"type": "integer"},
                        "confidence":     {"type": "float"},
                        "stage_sequence": {"type": "keyword"},
                        "detected_at":    {"type": "date"},
                        "attack_chain":   {"type": "keyword"},
                    }
                }
            )
    except Exception as e:
        logger.error("[CHAINS INDEX] Could not create: %s", e)


async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    await _ensure_alerts_index()
    for alert in alerts:
        fp  = _alert_fingerprint(alert)
        doc = alert.to_dict()
        doc["fingerprint"] = fp
        ok  = await _es_index_with_retry(ALERTS_INDEX, doc, doc_id=fp)
        if ok:
            logger.info(
                "[ALERT STORED] rule=%-15s severity=%-8s host=%s fp=%s",
                alert.rule_id, alert.severity, alert.host, fp,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: GRAPH CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════
async def _run_graph_correlation() -> list[dict]:
    graph_engine.link_events()
    chains = graph_engine.detect_attack_chain()
    if chains:
        await _ensure_chains_index()
        for chain in chains:
            stored = await _es_index_with_retry(
                CHAINS_INDEX,
                chain,
                doc_id=chain["chain_id"],
            )
            if stored:
                logger.warning(
                    "[CHAIN STORED] pattern='%s' chain_id=%s "
                    "risk=%d severity=%s confidence=%.0f%% stages=%s",
                    chain["pattern_name"], chain["chain_id"],
                    chain["risk_score"], chain["severity"],
                    chain["confidence"] * 100,
                    " → ".join(chain["stage_sequence"]),
                )
    summary = graph_engine.graph_summary()
    logger.info(
        "[GRAPH STATE] nodes=%d edges=%d components=%d seen_chains=%d",
        summary["nodes"], summary["edges"],
        summary.get("components", 0), summary.get("chains_detected", 0),
    )
    return chains


# ═══════════════════════════════════════════════════════════════════════════════
# INGESTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    client_ip  = _get_client_ip(request)
    nxlog_flag = _is_nxlog(request)

    if not _check_rate_limit(client_ip, nxlog_flag):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")
    source, payload = _parse_body(content_type, raw_body)

    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Normalization failed: {exc}")

    doc = _prep_doc(normalized)
    await _es_index_with_retry(get_index(), doc, doc_id=normalized.id)

    event_for_detector = _build_detector_event(doc, payload)
    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        for alert in alerts:
            graph_engine.add_alert(alert.to_dict())
        await _run_graph_correlation()

    return {
        "id":       normalized.id,
        "alerts":   len(alerts),
        "is_nxlog": nxlog_flag,
    }


@app.post("/logs/bulk", response_model=BulkIngestionResponse, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    client_ip  = _get_client_ip(request)
    nxlog_flag = _is_nxlog(request)

    if not _check_rate_limit(client_ip, nxlog_flag):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    try:
        items = json.loads(raw_body.decode("utf-8", errors="replace"))
        if not isinstance(items, list):
            items = [items]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON array: {exc}")

    accepted_ids:  list[str]   = []
    errors:        list[str]   = []
    bulk_ops:      list        = []
    all_alerts:    list[Alert] = []
    total_chains:  int         = 0

    for i, item in enumerate(items):
        try:
            if "payload" in item:
                source  = item.get("source", "nxlog")
                payload = item.get("payload", {})
            else:
                source, payload = "nxlog", item

            normalized = normalize(LogSource(source), payload)
            doc        = _prep_doc(normalized)
            bulk_ops.append({"index": {"_index": get_index(), "_id": normalized.id}})
            bulk_ops.append(doc)
            accepted_ids.append(normalized.id)

            event_for_detector = _build_detector_event(doc, payload)
            try:
                item_alerts = detect(event_for_detector)
            except Exception as det_err:
                logger.error("[BULK DETECT] item=%d error=%r", i, det_err)
                item_alerts = []

            all_alerts.extend(item_alerts)
            for alert in item_alerts:
                graph_engine.add_alert(alert.to_dict())

        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

    if all_alerts:
        await _index_alerts(all_alerts)

    if all_alerts:
        chains       = await _run_graph_correlation()
        total_chains = len(chains)
        logger.warning(
            "[BULK] items=%d accepted=%d alerts=%d chains=%d errors=%d",
            len(items), len(accepted_ids), len(all_alerts),
            total_chains, len(errors),
        )

    return BulkIngestionResponse(
        success  = len(errors) == 0,
        accepted = len(accepted_ids),
        rejected = len(errors),
        log_ids  = accepted_ids,
        errors   = errors,
    )


# ── GET /logs ──────────────────────────────────────────────────────────────────
@app.get("/logs", response_model=list[LogResponse], tags=["Query"])
async def get_logs(
    event_type: Optional[EventType] = Query(None),
    user:       Optional[str]       = Query(None),
    host:       Optional[str]       = Query(None),
    process:    Optional[str]       = Query(None),
    since:      Optional[datetime]  = Query(None),
    limit:      int                 = Query(100, le=1000),
):
    must = []
    if event_type: must.append({"term":     {"event_type": event_type.value}})
    if user:       must.append({"wildcard": {"user":            {"value": f"*{user}*",    "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":            {"value": f"*{host}*",    "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*", "case_insensitive": True}}})
    if since:      must.append({"range":    {"timestamp":       {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    res   = await es.search(
        index = get_index(),
        query = query,
        sort  = [{"timestamp": {"order": "desc"}}],
        size  = limit,
    )
    return [LogResponse(**hit["_source"]) for hit in res["hits"]["hits"]]


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────
@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── GET /alerts ────────────────────────────────────────────────────────────────
@app.get("/alerts", tags=["Detection"])
async def get_alerts(
    severity:  Optional[str]      = Query(None, description="critical|high|medium|low"),
    tactic:    Optional[str]      = Query(None),
    host:      Optional[str]      = Query(None),
    rule_id:   Optional[str]      = Query(None),
    since:     Optional[datetime] = Query(None),
    limit:     int                = Query(50, le=500),
):
    must = []
    if severity: must.append({"term":     {"severity": severity}})
    if tactic:   must.append({"wildcard": {"tactic":   {"value": f"*{tactic}*", "case_insensitive": True}}})
    if host:     must.append({"wildcard": {"host":     {"value": f"*{host}*",   "case_insensitive": True}}})
    if rule_id:  must.append({"term":     {"rule_id":  rule_id}})
    if since:    must.append({"range":    {"timestamp": {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    try:
        res = await es.search(
            index = ALERTS_INDEX,
            query = query,
            sort  = [{"timestamp": {"order": "desc"}}],
            size  = limit,
        )
    except Exception:
        return []

    alerts = []
    for hit in res["hits"]["hits"]:
        alert = hit["_source"].copy()

        # [P5-FIX-TIME] Always return HH:MM:SS — never null or empty.
        # Handles None, empty string, missing key, and malformed ISO values.
        # Falls back to current UTC time so downstream consumers always get
        # a valid time string regardless of what ES stored.
        raw_ts = alert.get("timestamp") or ""
        try:
            parsed_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            parsed_ts = datetime.now(timezone.utc)
            logger.warning(
                "[ALERTS] Invalid or missing timestamp %r — "
                "using current UTC time. rule=%s host=%s",
                raw_ts,
                alert.get("rule_id", "unknown"),
                alert.get("host",    "unknown"),
            )
        alert["time"] = parsed_ts.strftime("%H:%M:%S")

        alerts.append(alert)

    return alerts


# ── GET /alerts/summary ────────────────────────────────────────────────────────
@app.get("/alerts/summary", tags=["Detection"])
async def alerts_summary():
    es = get_es()
    try:
        res = await es.search(
            index = ALERTS_INDEX,
            size  = 0,
            aggs  = {
                "by_severity": {"terms": {"field": "severity", "size": 5}},
                "by_tactic":   {"terms": {"field": "tactic",   "size": 10}},
                "by_rule":     {"terms": {"field": "rule_id",  "size": 20}},
                "by_host":     {"terms": {"field": "host",     "size": 10}},
                "timeline":    {
                    "date_histogram": {
                        "field":             "timestamp",
                        "calendar_interval": "hour",
                    }
                },
            },
        )
    except Exception:
        return {"total": 0, "by_severity": {}, "by_tactic": {},
                "by_rule": {}, "by_host": {}, "timeline": []}

    aggs = res["aggregations"]
    return {
        "total":       res["hits"]["total"]["value"],
        "by_severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
        "by_tactic":   {b["key"]: b["doc_count"] for b in aggs["by_tactic"]["buckets"]},
        "by_rule":     {b["key"]: b["doc_count"] for b in aggs["by_rule"]["buckets"]},
        "by_host":     {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]},
        "timeline":    [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
        ],
    }


# ── GET /logs/stats/summary ────────────────────────────────────────────────────
@app.get("/logs/stats/summary", tags=["Analytics"])
async def log_summary():
    es  = get_es()
    res = await es.search(
        index = get_index(),
        size  = 0,
        aggs  = {
            "by_type":  {"terms": {"field": "event_type", "size": 20}},
            "by_host":  {"terms": {"field": "host",       "size": 10}},
            "timeline": {
                "date_histogram": {
                    "field":             "timestamp",
                    "calendar_interval": "hour",
                }
            },
            "avg_latency_ms": {
                "avg": {
                    "script": {
                        "source": (
                            "doc['ingested_at'].value.toInstant().toEpochMilli() "
                            "- doc['timestamp'].value.toInstant().toEpochMilli()"
                        )
                    }
                }
            },
        },
    )
    aggs = res["aggregations"]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]},
        "by_host":        {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]},
        "timeline":       [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
        ],
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /chains ────────────────────────────────────────────────────────────────
@app.get("/chains", tags=["Attack Graph"])
async def get_chains(
    severity:     Optional[str]      = Query(None, description="critical|high|medium|low"),
    pattern_name: Optional[str]      = Query(None),
    since:        Optional[datetime] = Query(None),
    limit:        int                = Query(20, le=200),
):
    must = []
    if severity:     must.append({"term":     {"severity":     severity}})
    if pattern_name: must.append({"wildcard": {"pattern_name": {"value": f"*{pattern_name}*", "case_insensitive": True}}})
    if since:        must.append({"range":    {"detected_at":  {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    try:
        res = await es.search(
            index = CHAINS_INDEX,
            query = query,
            sort  = [{"detected_at": {"order": "desc"}}],
            size  = limit,
        )
    except Exception:
        return {"total": 0, "chains": []}

    hits = [h["_source"] for h in res["hits"]["hits"]]
    return {"total": len(hits), "chains": hits}


# ── GET /graph/stats ──────────────────────────────────────────────────────────
@app.get("/graph/stats", tags=["Attack Graph"])
async def graph_stats():
    return {
        "engine":    "AttackGraphEngine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **graph_engine.graph_summary(),
    }


# ── POST /graph/reset ─────────────────────────────────────────────────────────
@app.post("/graph/reset", tags=["Attack Graph"])
async def reset_graph():
    graph_engine.reset()
    return {
        "success":   True,
        "message":   "Graph engine state cleared",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── GET /ai/analyze ───────────────────────────────────────────────────────────
@app.get("/ai/analyze", tags=["AI Analysis"])
async def ai_analyze_chain(
    chain_id: Optional[str] = Query(
        None,
        description=(
            "Specific chain_id to analyze. "
            "Omit to analyze the most recently detected chain."
        ),
    )
):
    """
    Fetch an attack chain from soc-chains and analyze it using Google Gemini
    acting as a senior SOC analyst.

    Pipeline in ai_engine.py:
      1. Smart trigger guard  — skips chains with risk_score < 50
      2. Cache lookup         — returns instantly if chain seen before (1h TTL)
      3. Hard rate limiter    — rejects if 15 RPM / 1500 RPD quota is full
      4. Gemini API call      — proper backoff on 429 (15s → 30s → 60s)
      5. Cache store          — saves result for future identical chains
    """
    es = get_es()

    try:
        if chain_id:
            try:
                res   = await es.get(index=CHAINS_INDEX, id=chain_id)
                chain = res["_source"]
            except Exception:
                raise HTTPException(
                    status_code=404,
                    detail=f"Chain '{chain_id}' not found in soc-chains index.",
                )
        else:
            res = await es.search(
                index = CHAINS_INDEX,
                query = {"match_all": {}},
                sort  = [{"detected_at": {"order": "desc"}}],
                size  = 1,
            )
            hits = res["hits"]["hits"]
            if not hits:
                return JSONResponse(
                    status_code=404,
                    content={
                        "error":     "No attack chains found in soc-chains index.",
                        "hint":      "Ingest logs first to generate chains via POST /logs",
                        "chain":     None,
                        "analysis":  None,
                        "ai_status": get_rate_limit_status(),
                    },
                )
            chain = hits[0]["_source"]

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[AI ANALYZE] Elasticsearch query failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch unavailable — cannot fetch attack chains.",
        )

    try:
        analysis = analyze_chain(chain)
    except Exception as exc:
        logger.exception("[AI ANALYZE] Unexpected error from analyze_chain")
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed unexpectedly: {exc!r}",
        )

    logger.info(
        "[AI ANALYZE] Done | chain_id=%s pattern=%s",
        chain.get("chain_id", "N/A"),
        chain.get("pattern_name", "N/A"),
    )

    return {
        "chain":     chain,
        "analysis":  analysis,
        "ai_status": get_rate_limit_status(),
    }


# ── GET /ai/status ────────────────────────────────────────────────────────────
@app.get("/ai/status", tags=["AI Analysis"])
async def ai_status():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **get_rate_limit_status(),
    }


# ── POST /chat ─────────────────────────────────────────────────────────────────
@app.post("/chat", tags=["SOC Copilot"])
async def chat_endpoint(body: dict):
    """
    Ask the SOC Copilot anything about your current threat landscape.

    Request body:  { "query": "Are there any lateral movement indicators?" }
    """
    query = body.get("query")
    if not query:
        return {"error": "Query is required"}
    return await chat_with_ai(query)


# ── Debug / Admin ──────────────────────────────────────────────────────────────
@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    logger.info(f"[DEBUG RAW] ct={request.headers.get('content-type')} ua={request.headers.get('user-agent')}")
    logger.info(f"[DEBUG RAW] body={json.dumps(parsed, default=str)[:500]}")
    return {"received": parsed, "size_bytes": len(body)}


@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    await reset_index()
    return {"success": True, "message": "soc-logs index recreated"}


@app.post("/admin/reset-alerts", tags=["Admin"])
async def admin_reset_alerts():
    es = get_es()
    try:
        await es.indices.delete(index=ALERTS_INDEX)
    except Exception:
        pass
    return {"success": True, "message": "soc-alerts index deleted"}


@app.post("/admin/reset-chains", tags=["Admin"])
async def admin_reset_chains():
    es = get_es()
    try:
        await es.indices.delete(index=CHAINS_INDEX)
    except Exception:
        pass
    graph_engine.reset()
    return {"success": True, "message": "soc-chains index deleted and graph engine reset"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
