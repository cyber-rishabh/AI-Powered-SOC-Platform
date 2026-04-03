"""
main.py — SOC Backend Phase 1 (Elasticsearch, production-grade)
Run:  uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import (
    BulkLogIngestion,
    BulkIngestionResponse,
    LogResponse, EventType, LogSource,
)
from normalizer import normalize


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 1",
    description = "Elite SOC pipeline: NXLog → FastAPI → Elasticsearch",
    version     = "4.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rate limiter ───────────────────────────────────────────────────────────────

_rate_limit_store: dict[str, list[float]] = {}
RATE_LIMIT_REQUESTS = 10000
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


# ── Helper ─────────────────────────────────────────────────────────────────────

def _prep_doc(log) -> dict:
    """Convert NormalizedLog to ES-ready dict (ISO strings for dates)."""
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────
# Accepts TWO formats so both NXLog (raw flat JSON) and manual curl tests work:
#
#   FORMAT A — NXLog CE sends this (raw flat JSON, no wrapper):
#   { "EventID": "4625", "Hostname": "WIN10", "TargetUserName": "admin", ... }
#
#   FORMAT B — curl tests / structured clients send this:
#   { "source": "nxlog", "payload": { "EventID": "4625", ... } }
#
# Detection: if "payload" key is absent → it's Format A → wrap it automatically.
# This means NXLog needs ZERO changes to send raw JSON and it will just work.

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    """
    Ingest one log. Accepts raw NXLog JSON or wrapped {source, payload} format.
    Never returns 422 — bad events return {success: false, error: ...} with 200
    so NXLog doesn't retry endlessly on normalization failures.
    """
     if "nxlog" not in user_agent.lower():
        if not _check_rate_limit(_get_client_ip(request)):
         return JSONResponse(
            status_code=429,
            content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
         )

 # ── Parse body ────────────────────────────────────────────────────────────
    try:
        raw_body = await request.body()
        data     = json.loads(raw_body)
    except Exception as e:
        logger.error(f"[PARSE ERROR] Could not parse JSON body: {e}")
        logger.error(f"[PARSE ERROR] Raw bytes: {raw_body[:500]}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": f"Invalid JSON: {e}"}
        )

    # ── Auto-detect format ────────────────────────────────────────────────────
    if "payload" not in data:
        # FORMAT A: NXLog sent raw flat JSON — wrap it
        source  = "nxlog"
        payload = data
        logger.info(f"[INGEST] Format A (raw NXLog) — EventID={data.get('EventID')} Host={data.get('Hostname')}")
    else:
        # FORMAT B: already wrapped — use as-is
        source  = data.get("source", "nxlog")
        payload = data.get("payload", {})
        logger.info(f"[INGEST] Format B (wrapped) — source={source} EventID={payload.get('EventID')}")

    # ── Normalize ─────────────────────────────────────────────────────────────
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        # Log full payload for debugging — visible in uvicorn terminal
        logger.error(f"[NORMALIZE ERROR] {e}")
        logger.error(f"[NORMALIZE ERROR] source={source}")
        logger.error(f"[NORMALIZE ERROR] payload={json.dumps(payload, default=str)[:1000]}")
        # Return 200 (not 422) so NXLog doesn't retry forever
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"}
        )

    # ── Index into ES ─────────────────────────────────────────────────────────
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] Failed to index log {normalized.id}: {e}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"}
        )

    logger.info(f"[OK] {normalized.event_type.value} | user={normalized.user} | host={normalized.host} | id={normalized.id[:8]}")

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    """
    Batch ingest. Accepts:
      { "logs": [ <Format A or B>, ... ] }
    Each item can be raw NXLog JSON or wrapped — same auto-detection as /logs.
    """
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

    for i, item in enumerate(items):
        try:
            if "payload" not in item:
                source, payload = "nxlog", item
            else:
                source  = item.get("source", "nxlog")
                payload = item.get("payload", {})

            normalized = normalize(LogSource(source), payload)
            doc        = _prep_doc(normalized)
            bulk_ops.append({"index": {"_index": get_index(), "_id": normalized.id}})
            bulk_ops.append(doc)
            accepted_ids.append(normalized.id)
        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")
            logger.error(f"[BULK ERROR] item {i}: {e} | data={json.dumps(item, default=str)[:300]}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

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
    if event_type: must.append({"term":     {"event_type":      event_type.value}})
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


# ── GET /logs/stats/summary ────────────────────────────────────────────────────

@app.get("/logs/stats/summary", tags=["Analytics"])
async def log_summary():
    es  = get_es()
    res = await es.search(
        index = get_index(),
        size  = 0,
        aggs  = {
            "by_type": {"terms": {"field": "event_type", "size": 20}},
            "by_host": {"terms": {"field": "host",       "size": 10}},
            "timeline": {
                "date_histogram": {
                    "field":             "timestamp",
                    "calendar_interval": "hour",
                }
            },
            "avg_latency_ms": {
                "avg": {
                    "script": {
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"]
        if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    """
    Temporarily point NXLog here to see the exact raw payload it sends.
    Check uvicorn terminal output after triggering a Windows event.
    """
    body = await request.body()
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = body.decode(errors="replace")

    logger.info(f"[DEBUG RAW] Headers: {dict(request.headers)}")
    logger.info(f"[DEBUG RAW] Body: {json.dumps(parsed, indent=2, default=str)}")
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    """Drop + recreate soc-logs index with correct mapping. Deletes all data."""
    await reset_index()
    return {"success": True, "message": "Index recreated with dynamic:false mapping"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 1 (Elasticsearch, production-grade)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import (
    BulkIngestionResponse,
    LogResponse, EventType, LogSource,
)
from normalizer import normalize


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 1",
    description = "Elite SOC pipeline: NXLog → FastAPI → Elasticsearch",
    version     = "4.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rate limiter ───────────────────────────────────────────────────────────────

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


# ── Helper ─────────────────────────────────────────────────────────────────────

def _prep_doc(log) -> dict:
    """Convert NormalizedLog to ES-ready dict (ISO strings for dates)."""
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────
# Accepts THREE formats so NXLog (raw flat JSON), NXLog with "message" wrapper,
# and manual curl tests all work without any NXLog-side changes:
#
#   FORMAT A — NXLog CE sends raw flat JSON (no wrapper):
#   { "EventID": "4625", "Hostname": "WIN10", "TargetUserName": "admin", ... }
#
#   FORMAT B — curl tests / structured clients send this:
#   { "source": "nxlog", "payload": { "EventID": "4625", ... } }
#
#   FORMAT C — NXLog sends a single "message" string (raw Windows log):
#   { "message": "Security  Audit Failure  ...4625..." }
#
# Detection priority:
#   1. Has "payload" key        → Format B (already wrapped)
#   2. Has "message" key only   → Format C (NXLog raw string) → parse it
#   3. Anything else            → Format A (flat NXLog JSON) → use as payload
#
# NXLog needs ZERO config changes. Backend handles all variants.

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    """
    Ingest one log. Accepts:
      - Raw NXLog flat JSON
      - NXLog { "message": "raw string" } format
      - Wrapped { source, payload } format
    Never returns 422 — bad events return {success: false, error: ...} with 200
    so NXLog doesn't retry endlessly on normalization failures.
    """
    if not _check_rate_limit(_get_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
        )

    # ── Parse body ────────────────────────────────────────────────────────────
    try:
        raw_body = await request.body()
        data     = json.loads(raw_body)
    except Exception as e:
        logger.error(f"[PARSE ERROR] Could not parse JSON body: {e}")
        logger.error(f"[PARSE ERROR] Raw bytes: {raw_body[:500]}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": f"Invalid JSON: {e}"}
        )

    # ── DEBUG: always print raw received payload ───────────────────────────
    print("[RAW RECEIVED]", json.dumps(data, indent=2, default=str))
    logger.info(f"[RAW RECEIVED] keys={list(data.keys())}")

    # ── Auto-detect format ────────────────────────────────────────────────────
    if "payload" in data:
        # FORMAT B: already wrapped — use as-is
        source  = data.get("source", "nxlog")
        payload = data.get("payload", {})
        logger.info(f"[INGEST] Format B (wrapped) — source={source} EventID={payload.get('EventID')}")

    elif "message" in data and len(data) <= 3:
        # FORMAT C: NXLog sent { "message": "raw windows log string" }
        # (may also contain "Hostname" and/or "EventReceivedTime" alongside message)
        source  = "nxlog"
        payload = _parse_message_string(data)
        logger.info(f"[INGEST] Format C (message string) — parsed EventID={payload.get('EventID')} Host={payload.get('Hostname')}")

    else:
        # FORMAT A: NXLog sent raw flat JSON — use directly as payload
        source  = "nxlog"
        payload = data
        logger.info(f"[INGEST] Format A (raw flat JSON) — EventID={data.get('EventID')} Host={data.get('Hostname')}")

    # ── Normalize ─────────────────────────────────────────────────────────────
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e}")
        logger.error(f"[NORMALIZE ERROR] source={source}")
        logger.error(f"[NORMALIZE ERROR] payload={json.dumps(payload, default=str)[:1000]}")
        # Return 200 (not 422) so NXLog doesn't retry forever
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"}
        )

    # ── Index into ES ─────────────────────────────────────────────────────────
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] Failed to index log {normalized.id}: {e}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"}
        )

    logger.info(f"[OK] {normalized.event_type.value} | user={normalized.user} | host={normalized.host} | id={normalized.id[:8]}")

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── Message string parser ──────────────────────────────────────────────────────

def _parse_message_string(data: dict) -> dict:
    """
    Parse Format C: { "message": "raw Windows log string", ... }
    Extracts EventID, user, IP, hostname from the raw string.
    Falls back gracefully — always returns a usable dict.
    """
    import re

    raw_msg  = data.get("message", "")
    hostname = data.get("Hostname", data.get("hostname", "unknown"))

    payload: dict = {
        "Hostname":    hostname,
        "raw_message": raw_msg,
    }

    # ── EventID ───────────────────────────────────────────────────────────────
    eid_match = re.search(r"\b(4624|4625|4634|4648|4720|4728|4732|4756|4776|7045|1102|4688)\b", raw_msg)
    if eid_match:
        payload["EventID"] = eid_match.group(1)

    # ── Username ──────────────────────────────────────────────────────────────
    for pattern in [
        r"(?:Account Name|TargetUserName|SubjectUserName)[\s:]+([^\s\r\n]+)",
        r"user[:\s]+([a-zA-Z0-9_\\.-]+)",
    ]:
        m = re.search(pattern, raw_msg, re.IGNORECASE)
        if m:
            payload["TargetUserName"] = m.group(1).strip()
            break

    # ── Source IP ─────────────────────────────────────────────────────────────
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw_msg)
    if ip_match:
        payload["IpAddress"] = ip_match.group(1)

    # ── Process name ─────────────────────────────────────────────────────────
    proc_match = re.search(r"(?:Process Name|New Process Name)[\s:]+([^\r\n]+)", raw_msg, re.IGNORECASE)
    if proc_match:
        payload["ProcessName"] = proc_match.group(1).strip()

    logger.info(f"[PARSE MSG] Extracted: EventID={payload.get('EventID')} user={payload.get('TargetUserName')} ip={payload.get('IpAddress')}")
    return payload


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    """
    Batch ingest. Accepts:
      { "logs": [ <Format A, B, or C>, ... ] }
    Each item uses same auto-detection as /logs.
    """
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

    for i, item in enumerate(items):
        try:
            if "payload" in item:
                source  = item.get("source", "nxlog")
                payload = item.get("payload", {})
            elif "message" in item and len(item) <= 3:
                source  = "nxlog"
                payload = _parse_message_string(item)
            else:
                source  = "nxlog"
                payload = item

            normalized = normalize(LogSource(source), payload)
            doc        = _prep_doc(normalized)
            bulk_ops.append({"index": {"_index": get_index(), "_id": normalized.id}})
            bulk_ops.append(doc)
            accepted_ids.append(normalized.id)
        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")
            logger.error(f"[BULK ERROR] item {i}: {e} | data={json.dumps(item, default=str)[:300]}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

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
    if event_type: must.append({"term":     {"event_type":      event_type.value}})
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


# ── GET /logs/stats/summary ────────────────────────────────────────────────────

@app.get("/logs/stats/summary", tags=["Analytics"])
async def log_summary():
    es  = get_es()
    res = await es.search(
        index = get_index(),
        size  = 0,
        aggs  = {
            "by_type": {"terms": {"field": "event_type", "size": 20}},
            "by_host": {"terms": {"field": "host",       "size": 10}},
            "timeline": {
                "date_histogram": {
                    "field":             "timestamp",
                    "calendar_interval": "hour",
                }
            },
            "avg_latency_ms": {
                "avg": {
                    "script": {
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"]
        if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    """
    Temporarily point NXLog here to see the exact raw payload it sends.
    Check uvicorn terminal output after triggering a Windows event.
    """
    body = await request.body()
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = body.decode(errors="replace")

    logger.info(f"[DEBUG RAW] Headers: {dict(request.headers)}")
    logger.info(f"[DEBUG RAW] Body: {json.dumps(parsed, indent=2, default=str)}")
    print("[DEBUG RAW BODY]", json.dumps(parsed, indent=2, default=str))
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    """Drop + recreate soc-logs index with correct mapping. Deletes all data."""
    await reset_index()
    return {"success": True, "message": "Index recreated with dynamic:false mapping"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 1 (Elasticsearch, production-grade)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import (
    BulkIngestionResponse,
    LogResponse, EventType, LogSource,
)
from normalizer import normalize


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 1",
    description = "Elite SOC pipeline: NXLog → FastAPI → Elasticsearch",
    version     = "4.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rate limiter ───────────────────────────────────────────────────────────────

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


# ── Helper ─────────────────────────────────────────────────────────────────────

def _prep_doc(log) -> dict:
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Body parser ────────────────────────────────────────────────────────────────
# Handles ALL formats NXLog CE can send:
#
#  FORMAT A — flat JSON (never actually arrives from CE 3.2, but keep for curl)
#    { "EventID": "4625", "Hostname": "WIN10", ... }
#
#  FORMAT B — wrapped JSON (curl tests)
#    { "source": "nxlog", "payload": { ... } }
#
#  FORMAT C — plain text syslog (what NXLog CE 3.2 actually sends)
#    <14>2026-03-26T01:14:34Z WIN10 MSWinEventLog ...
#    ContentType: text/plain
#
# Detection order:
#   1. ContentType contains "json"  → try JSON parse → Format A or B
#   2. Body starts with "{"         → try JSON parse → Format A or B
#   3. Anything else                → treat as raw syslog string → Format C

def _parse_body(content_type: str, raw_body: bytes) -> tuple[str, dict]:
    """
    Returns (source, payload) ready for normalize().
    Never raises — always returns something usable.
    """
    body_str = raw_body.decode("utf-8", errors="replace").strip()

    # ── Try JSON first ────────────────────────────────────────────────────────
    is_json_content = "json" in content_type.lower()
    looks_like_json = body_str.startswith("{")

    if is_json_content or looks_like_json:
        try:
            data = json.loads(body_str)
            if "payload" in data:
                return data.get("source", "nxlog"), data.get("payload", {})
            else:
                return "nxlog", data
        except json.JSONDecodeError:
            # Malformed JSON — fall through to syslog parser
            logger.warning(f"[PARSE] ContentType={content_type} but JSON parse failed, trying syslog")

    # ── Treat as raw syslog text (Format C — NXLog CE 3.2 default) ───────────
    logger.info(f"[PARSE] Treating body as raw syslog text")
    payload = _parse_syslog_string(body_str)
    return "nxlog", payload


def _parse_syslog_string(raw: str) -> dict:
    """
    Parse a raw syslog line or any unstructured Windows log string.
    Extracts every useful field we can find and returns a flat dict
    compatible with normalize().
    """
    payload: dict = {"raw_message": raw}

    # Hostname — appears early in syslog: <PRI>TIMESTAMP HOSTNAME ...
    host_match = re.search(
        r"^(?:<\d+>)?(?:\S+\s+)?\S+\s+(\S+)\s+",
        raw
    )
    if host_match:
        payload["Hostname"] = host_match.group(1)

    # EventID — look for 4-digit Windows event IDs we care about
    eid_match = re.search(
        r"\b(4624|4625|4634|4647|4648|4672|4688|4720|4724|4728|4732|4756|4776|7045|1102)\b",
        raw
    )
    if eid_match:
        payload["EventID"] = eid_match.group(1)

    # Username
    for pattern in [
        r"(?:Account Name|TargetUserName|SubjectUserName)\s*[=:]\s*(\S+)",
        r"user[=:\s]+([a-zA-Z0-9_\\.\-]+)",
    ]:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            val = m.group(1).strip("'\"")
            if val not in ("-", "SYSTEM", ""):
                payload["TargetUserName"] = val
                break

    # Source IP
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw)
    if ip_match:
        payload["IpAddress"] = ip_match.group(1)

    # Process name
    proc_match = re.search(
        r"(?:Process Name|New Process Name)\s*[=:]\s*([^\r\n;]+)",
        raw, re.IGNORECASE
    )
    if proc_match:
        payload["ProcessName"] = proc_match.group(1).strip()

    logger.info(
        f"[PARSE SYSLOG] EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} "
        f"host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')}"
    )
    return payload


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    """
    Ingest one log. Accepts:
      - NXLog CE plain text syslog  (ContentType: text/plain)
      - Raw flat JSON                (ContentType: application/json)
      - Wrapped { source, payload }  (ContentType: application/json)
    Never returns 422 so NXLog does not retry endlessly.
    """
    if not _check_rate_limit(_get_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
        )

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    # DEBUG — see exactly what NXLog sends in uvicorn terminal
    print(f"[RAW RECEIVED] content-type={content_type}")
    print(f"[RAW RECEIVED] body={raw_body[:500]}")

    # ── Parse ──────────────────────────────────────────────────────────────────
    try:
        source, payload = _parse_body(content_type, raw_body)
    except Exception as e:
        logger.error(f"[PARSE ERROR] {e} | body={raw_body[:300]}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": f"Parse error: {e}"}
        )

    # ── Normalize ──────────────────────────────────────────────────────────────
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e} | payload={json.dumps(payload, default=str)[:500]}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"}
        )

    # ── Index ──────────────────────────────────────────────────────────────────
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"}
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | id={normalized.id[:8]}"
    )
    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")
            logger.error(f"[BULK ERROR] item {i}: {e}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

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
    if event_type: must.append({"term":     {"event_type":      event_type.value}})
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
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"]
        if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = body.decode(errors="replace")
    print("[DEBUG RAW] content-type:", request.headers.get("content-type"))
    print("[DEBUG RAW] body:", parsed)
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    await reset_index()
    return {"success": True, "message": "Index recreated"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 1 (Elasticsearch, production-grade)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import (
    BulkIngestionResponse,
    LogResponse, EventType, LogSource,
)
from normalizer import normalize


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 1",
    description = "Elite SOC pipeline: NXLog → FastAPI → Elasticsearch",
    version     = "4.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rate limiter ───────────────────────────────────────────────────────────────

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


# ── Helper ─────────────────────────────────────────────────────────────────────

def _prep_doc(log) -> dict:
    doc = log.model_dump()
    doc["timestamp"]   = doc["timestamp"].isoformat()
    doc["ingested_at"] = doc["ingested_at"].isoformat()
    return doc


# ── Body parser ────────────────────────────────────────────────────────────────
# NXLog CE 3.2 sends syslog lines like:
#
#   <14>1 2026-03-26T01:28:23Z DESKTOP-R8PMJ31 Microsoft-Windows-Security-Auditing 4 -
#   [NXLOG@14506 Keywords="-9214..." EventType="AUDIT_SUCCESS" EventID="4688"
#   SubjectUserName="DESKTOP-R8PMJ31$" ...]
#
# Key points:
#  - EventID is inside the structured data block: EventID="4688"  (quoted)
#  - Username is SubjectUserName="..." or AccountName="..."       (quoted)
#  - Hostname is the 4th field in the syslog header
#  - ContentType is text/plain

def _parse_body(content_type: str, raw_body: bytes) -> tuple[str, dict]:
    body_str = raw_body.decode("utf-8", errors="replace").strip()

    is_json = "json" in content_type.lower() or body_str.startswith("{")
    if is_json:
        try:
            data = json.loads(body_str)
            if "payload" in data:
                return data.get("source", "nxlog"), data.get("payload", {})
            return "nxlog", data
        except json.JSONDecodeError:
            logger.warning("[PARSE] JSON parse failed, falling back to syslog parser")

    logger.info("[PARSE] Treating body as raw syslog text")
    return "nxlog", _parse_syslog_string(body_str)


def _parse_syslog_string(raw: str) -> dict:
    """
    Parse NXLog CE syslog format:

      <PRI>VERSION TIMESTAMP HOSTNAME APP PID MSGID
      [NXLOG@14506 Key="Value" Key="Value" ...]

    All fields inside [...] are Key="Value" pairs.
    We extract them all into a flat dict, then map
    to the field names normalize() expects.
    """
    payload: dict = {"raw_message": raw}

    # ── Extract all Key="Value" pairs from the structured data block ──────────
    # Covers: EventID="4688" SubjectUserName="admin" IpAddress="10.0.0.1" etc.
    kv_pairs = dict(re.findall(r'(\w+)="([^"]*)"', raw))

    # ── EventID ───────────────────────────────────────────────────────────────
    # Present as EventID="4688" in the structured block
    event_id = kv_pairs.get("EventID", "")
    if event_id:
        payload["EventID"] = event_id

    # ── Hostname ──────────────────────────────────────────────────────────────
    # Syslog header: <14>1 TIMESTAMP HOSTNAME APP PID MSGID [...]
    # Field index:    0    1          2        3   4   5
    parts = raw.split()
    if len(parts) >= 4:
        # parts[0] = <14>1, parts[1] = timestamp, parts[2] = hostname
        hostname = parts[2]
        if hostname not in ("-", ""):
            payload["Hostname"] = hostname

    # Override with structured data if present
    if "Hostname" in kv_pairs:
        payload["Hostname"] = kv_pairs["Hostname"]

    # ── Username ──────────────────────────────────────────────────────────────
    # NXLog CE uses these field names (in priority order)
    for field in ["TargetUserName", "SubjectUserName", "AccountName", "UserName"]:
        val = kv_pairs.get(field, "").strip()
        # Skip machine accounts (end with $), empty, or placeholder values
        if val and not val.endswith("$") and val not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            payload["TargetUserName"] = val
            break

    # ── Source IP ─────────────────────────────────────────────────────────────
    for field in ["IpAddress", "SourceAddress", "WorkstationName"]:
        val = kv_pairs.get(field, "").strip()
        if val and val not in ("-", "::1", "127.0.0.1"):
            # Validate it looks like an IP
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
                payload["IpAddress"] = val
                break

    # ── Process name ──────────────────────────────────────────────────────────
    for field in ["NewProcessName", "ProcessName", "Application"]:
        val = kv_pairs.get(field, "").strip()
        if val and val not in ("-", ""):
            payload["ProcessName"] = val
            break

    # ── Logon type (useful for 4624/4625) ────────────────────────────────────
    if "LogonType" in kv_pairs:
        payload["LogonType"] = kv_pairs["LogonType"]

    logger.info(
        f"[PARSE SYSLOG] EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} "
        f"host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')}"
    )
    return payload


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        return JSONResponse(
            status_code=429,
            content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
        )

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    print(f"[RAW RECEIVED] content-type={content_type}")
    print(f"[RAW RECEIVED] body={raw_body[:300]}")

    try:
        source, payload = _parse_body(content_type, raw_body)
    except Exception as e:
        logger.error(f"[PARSE ERROR] {e} | body={raw_body[:300]}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": f"Parse error: {e}"}
        )

    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e} | payload={json.dumps(payload, default=str)[:500]}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"}
        )

    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"}
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | id={normalized.id[:8]}"
    )
    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
        except Exception as e:
            errors.append(f"Item {i}: {str(e)}")
            logger.error(f"[BULK ERROR] item {i}: {e}")

    if bulk_ops:
        es       = get_es()
        response = await es.bulk(operations=bulk_ops)
        if response.get("errors"):
            for bulk_item in response["items"]:
                op = bulk_item.get("index", {})
                if op.get("error"):
                    errors.append(f"ES error for {op['_id']}: {op['error']['reason']}")
                    accepted_ids = [x for x in accepted_ids if x != op["_id"]]

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
    if event_type: must.append({"term":     {"event_type":      event_type.value}})
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
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"]
        if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = body.decode(errors="replace")
    print("[DEBUG RAW] content-type:", request.headers.get("content-type"))
    print("[DEBUG RAW] body:", parsed)
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

@app.post("/admin/reset-index", tags=["Admin"])
async def admin_reset_index():
    await reset_index()
    return {"success": True, "message": "Index recreated"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 2 (Threat Detection)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 2",
    description = "NXLog → FastAPI → Elasticsearch + Threat Detection",
    version     = "5.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"


# ── Rate limiter ───────────────────────────────────────────────────────────────

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


def _parse_syslog_string(raw: str) -> dict:
    """
    Parse NXLog CE syslog:
      <14>1 TIMESTAMP HOST APP PID - [NXLOG@14506 Key="Value" ...]
    Extract all Key="Value" pairs, map to normalizer field names.
    """
    payload: dict = {"raw_message": raw}

    # All structured Key="Value" pairs in one pass
    kv = dict(re.findall(r'(\w+)="([^"]*)"', raw))

    # EventID
    if kv.get("EventID"):
        payload["EventID"] = kv["EventID"]

    # Hostname from syslog header (field index 2)
    parts = raw.split()
    if len(parts) >= 3:
        h = parts[2]
        if h not in ("-", ""):
            payload["Hostname"] = h
    if kv.get("Hostname"):
        payload["Hostname"] = kv["Hostname"]

    # Username — skip machine accounts (end with $)
    for f in ["TargetUserName", "SubjectUserName", "AccountName", "UserName"]:
        v = kv.get(f, "").strip()
        if v and not v.endswith("$") and v not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            payload["TargetUserName"] = v
            break

    # Source IP
    for f in ["IpAddress", "SourceAddress"]:
        v = kv.get(f, "").strip()
        if v and v not in ("-", "::1", "127.0.0.1") and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            payload["IpAddress"] = v
            break

    # Process
    for f in ["NewProcessName", "ProcessName", "Application"]:
        v = kv.get(f, "").strip()
        if v and v not in ("-",):
            payload["ProcessName"] = v
            break

    # Logon type
    if kv.get("LogonType"):
        payload["LogonType"] = kv["LogonType"]

    # Pass all raw KV through so detector can access any field
    payload["_kv"] = kv

    logger.info(
        f"[PARSE SYSLOG] EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} "
        f"host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')}"
    )
    return payload


# ── Alert indexer ──────────────────────────────────────────────────────────────

async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    es = get_es()

    # Ensure alerts index exists
    try:
        exists = await es.indices.exists(index=ALERTS_INDEX)
        if not exists:
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "severity":  {"type": "keyword"},
                        "rule_id":   {"type": "keyword"},
                        "technique": {"type": "keyword"},
                        "tactic":    {"type": "keyword"},
                        "host":      {"type": "keyword"},
                        "user":      {"type": "keyword"},
                        "src_ip":    {"type": "ip",      "ignore_malformed": True},
                        "title":     {"type": "text"},
                        "description": {"type": "text"},
                    }
                }
            )
    except Exception as e:
        logger.error(f"[ALERTS INDEX] Could not create index: {e}")

    for alert in alerts:
        try:
            await es.index(index=ALERTS_INDEX, document=alert.to_dict())
        except Exception as e:
            logger.error(f"[ALERT INDEX ERROR] {alert.rule_id}: {e}")


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        return JSONResponse(status_code=429,
            content={"success": False, "error": "Rate limit exceeded"})

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    print(f"[RAW] ct={content_type} body={raw_body[:200]}")

    # Parse
    try:
        source, payload = _parse_body(content_type, raw_body)
    except Exception as e:
        return JSONResponse(status_code=400,
            content={"success": False, "error": f"Parse error: {e}"})

    # Normalize
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"})

    # Index log
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"})

    # ── THREAT DETECTION ───────────────────────────────────────────────────────
    # Build a flat event dict merging normalized fields + raw KV for detector
    event_for_detector = {
        **doc,
        **payload.get("_kv", {}),   # raw Key="Value" pairs from syslog
        "EventID":    payload.get("EventID",       doc.get("event_id", "")),
        "IpAddress":  payload.get("IpAddress",     doc.get("src_ip", "")),
        "LogonType":  payload.get("LogonType",     ""),
        "ProcessName":payload.get("ProcessName",   doc.get("process", "")),
        "raw_message":payload.get("raw_message",   ""),
    }

    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        logger.warning(
            f"[DETECTION] {len(alerts)} alert(s) from event "
            f"{doc.get('event_id')} | host={doc.get('host')}"
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | "
        f"alerts={len(alerts)} | id={normalized.id[:8]}"
    )

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "alerts":     len(alerts),
        "alert_ids":  [a.rule_id for a in alerts],
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
    if user:       must.append({"wildcard": {"user":       {"value": f"*{user}*",    "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":       {"value": f"*{host}*",    "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*", "case_insensitive": True}}})
    if since:      must.append({"range":    {"timestamp":  {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    res   = await es.search(
        index = get_index(),
        query = query,
        sort  = [{"timestamp": {"order": "desc"}}],
        size  = limit,
    )
    return [LogResponse(**hit["_source"]) for hit in res["hits"]["hits"]]


# ── GET /alerts ────────────────────────────────────────────────────────────────

@app.get("/alerts", tags=["Detection"])
async def get_alerts(
    severity:  Optional[str] = Query(None, description="critical|high|medium|low"),
    tactic:    Optional[str] = Query(None),
    host:      Optional[str] = Query(None),
    rule_id:   Optional[str] = Query(None),
    since:     Optional[datetime] = Query(None),
    limit:     int           = Query(50, le=500),
):
    """Return detected threat alerts, newest first."""
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
        return []  # index doesn't exist yet — no alerts fired
    return [hit["_source"] for hit in res["hits"]["hits"]]


# ── GET /alerts/summary ────────────────────────────────────────────────────────

@app.get("/alerts/summary", tags=["Detection"])
async def alerts_summary():
    """Aggregated alert counts by severity, tactic, rule, and host."""
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
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs    = res["aggregations"]
    by_type = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    print("[DEBUG RAW] ct:", request.headers.get("content-type"))
    print("[DEBUG RAW] body:", parsed)
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 2 (Threat Detection)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 2",
    description = "NXLog → FastAPI → Elasticsearch + Threat Detection",
    version     = "5.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"


# ── Rate limiter ───────────────────────────────────────────────────────────────

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
# PARSER — module-level constants (compiled once at import, reused per request)
# ═══════════════════════════════════════════════════════════════════════════════

# Matches Key="Value" pairs including hyphenated keys (Sub-Status, Logon-Type)
_RE_KV = re.compile(r'([\w\-]+)="([^"]*)"')

# Matches both EventID="4625" (already in KV) and bare EventID=4625
_RE_EVENTID = re.compile(r'\bEventID=(\d+)', re.IGNORECASE)

# Strict IPv4 — four octets, each 0-255
_RE_IPV4 = re.compile(
    r'^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$'
)

# NT AUTHORITY\* and similar service principal prefixes
_RE_SERVICE_PRINCIPAL = re.compile(r'^(nt authority|window manager|font driver host)\\', re.IGNORECASE)

# Usernames that are always noise — stored lowercase for O(1) lookup
_SKIP_USERS: frozenset[str] = frozenset({
    "-", "", "system", "local service", "network service",
    "anonymous logon", "iis apppool", "dwm-1", "umfd-0", "umfd-1",
})

# IPs that are loopback / placeholder — never useful for detection
_SKIP_IPS: frozenset[str] = frozenset({
    "-", "", "::1", "::ffff:127.0.0.1", "127.0.0.1", "0.0.0.0", "fe80::1",
})

# Username candidate fields — ordered by reliability
_USER_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName", "UserName")

# IP candidate fields — ordered by reliability
_IP_FIELDS = ("IpAddress", "SourceAddress", "SourceNetworkAddress")

# Process name candidate fields — ordered by reliability
_PROC_FIELDS = ("NewProcessName", "ProcessName", "Application")


def _parse_syslog_string(raw: str) -> dict:
    """
    Parse an NXLog CE syslog message into a structured dict for the normalizer.

    Handles real-world messiness of Windows Security + Sysmon logs:
      ▸ EventID in quoted ("4625") and bare (4625) forms
      ▸ Hyphenated key names  (Sub-Status, Logon-Type)
      ▸ Inconsistent username fields and service-account noise
      ▸ IPv4 addresses across several possible field names
      ▸ CommandLine buried inside structured data
      ▸ LogonType arriving as int or string
      ▸ Hostname from both syslog header and KV pairs

    Never raises — always returns a dict (may be partial on malformed input).

    Returned keys used downstream by normalize() and detect():
        raw_message, EventID, Hostname, TargetUserName,
        IpAddress, ProcessName, CommandLine, LogonType, _kv
    """

    # Always present — downstream code can always safely read raw_message
    payload: dict = {"raw_message": raw}

    try:

        # ── Step 1: Extract ALL Key="Value" pairs in a single pass ────────────
        # Using ([\w\-]+) captures hyphenated keys like Sub-Status, Logon-Type.
        # dict() keeps last occurrence of a duplicate key (matches Windows behaviour).
        kv: dict[str, str] = dict(_RE_KV.findall(raw))
        payload["_kv"] = kv                         # expose full KV to detector

        # ── Step 2: EventID ───────────────────────────────────────────────────
        # Priority 1 — already parsed into kv as EventID="4625"
        # Priority 2 — bare form EventID=4625 (no quotes, some NXLog versions)
        event_id = kv.get("EventID", "").strip()
        if not event_id:
            m = _RE_EVENTID.search(raw)
            if m:
                event_id = m.group(1)
        if event_id:
            payload["EventID"] = event_id

        # ── Step 3: Hostname ──────────────────────────────────────────────────
        # Priority 1 — KV field set by NXLog enrichment (most accurate)
        # Priority 2 — syslog RFC 5424 header token at position [3]:
        #   <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
        hostname = (kv.get("Hostname") or kv.get("Computer") or "").strip()
        if not hostname:
            parts = raw.split()
            if len(parts) >= 4 and parts[3] not in ("-", ""):
                hostname = parts[3]
        if hostname:
            payload["Hostname"] = hostname

        # ── Step 4: Username ──────────────────────────────────────────────────
        # Walk _USER_FIELDS in priority order; apply all noise filters.
        # Rejects:
        #   ▸ machine accounts         (trailing $)
        #   ▸ service principals       (NT AUTHORITY\*, Window Manager\*)
        #   ▸ well-known noise names   (_SKIP_USERS set, case-insensitive)
        #   ▸ empty / placeholder "-"
        for field in _USER_FIELDS:
            v = kv.get(field, "").strip()
            if not v:
                continue
            if v.endswith("$"):                         # machine account
                continue
            if _RE_SERVICE_PRINCIPAL.match(v):          # NT AUTHORITY\SYSTEM etc.
                continue
            if v.lower() in _SKIP_USERS:               # known noise (O(1))
                continue
            payload["TargetUserName"] = v
            break

        # ── Step 5: Source IP address ─────────────────────────────────────────
        # Walk _IP_FIELDS; validate as IPv4; reject loopback / placeholders.
        for field in _IP_FIELDS:
            v = kv.get(field, "").strip()
            if not v or v in _SKIP_IPS:
                continue
            if _RE_IPV4.match(v):                       # strict IPv4 match
                payload["IpAddress"] = v
                break
            # Non-IPv4 but non-trivial — could be IPv6, accept cautiously
            if len(v) > 4:
                payload["IpAddress"] = v
                break

        # ── Step 6: Process name ──────────────────────────────────────────────
        # Return the raw path value; detector normalises to basename itself.
        for field in _PROC_FIELDS:
            v = kv.get(field, "").strip()
            if v and v != "-":
                payload["ProcessName"] = v
                break

        # ── Step 7: CommandLine ───────────────────────────────────────────────
        # Explicit extraction — critical for LOLBin / encoded PowerShell rules.
        # Fall back to direct regex scan in case KV parse missed it (e.g. value
        # contained an escaped quote that broke the KV boundary).
        cmdline = kv.get("CommandLine", "").strip()
        if not cmdline:
            m = re.search(r'CommandLine="([^"]*)"', raw)
            if m:
                cmdline = m.group(1)
        if cmdline:
            payload["CommandLine"] = cmdline

        # ── Step 8: LogonType ─────────────────────────────────────────────────
        # Coerce to clean string — detector compares with  == "3",  == "10", etc.
        # Also handles the hyphenated variant "Logon-Type" seen in some configs.
        logon_raw = (kv.get("LogonType") or kv.get("Logon-Type") or "").strip()
        if logon_raw:
            # If it's a digit string (possibly with leading zeros) normalise it
            payload["LogonType"] = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw

    except Exception as exc:
        # Safety net — log and continue; never crash the ingestion pipeline
        logger.error(
            f"[PARSE SYSLOG] Unexpected error: {exc!r} "
            f"| raw[:200]={raw[:200]!r}"
        )

    logger.info(
        "[PARSE SYSLOG] "
        f"EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} "
        f"host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')} "
        f"proc={payload.get('ProcessName')} "
        f"cmdline={'yes' if payload.get('CommandLine') else 'no'} "
        f"logon_type={payload.get('LogonType')}"
    )
    return payload


# ── Alert indexer ──────────────────────────────────────────────────────────────

async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    es = get_es()

    try:
        exists = await es.indices.exists(index=ALERTS_INDEX)
        if not exists:
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp":   {"type": "date"},
                        "severity":    {"type": "keyword"},
                        "rule_id":     {"type": "keyword"},
                        "technique":   {"type": "keyword"},
                        "tactic":      {"type": "keyword"},
                        "host":        {"type": "keyword"},
                        "user":        {"type": "keyword"},
                        "src_ip":      {"type": "ip", "ignore_malformed": True},
                        "title":       {"type": "text"},
                        "description": {"type": "text"},
                    }
                }
            )
    except Exception as e:
        logger.error(f"[ALERTS INDEX] Could not create index: {e}")

    for alert in alerts:
        try:
            await es.index(index=ALERTS_INDEX, document=alert.to_dict())
        except Exception as e:
            logger.error(f"[ALERT INDEX ERROR] {alert.rule_id}: {e}")


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        return JSONResponse(status_code=429,
            content={"success": False, "error": "Rate limit exceeded"})

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    print(f"[RAW] ct={content_type} body={raw_body[:200]}")

    try:
        source, payload = _parse_body(content_type, raw_body)
    except Exception as e:
        return JSONResponse(status_code=400,
            content={"success": False, "error": f"Parse error: {e}"})

    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"})

    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"})

    # Build detector event — merge normalized doc + raw KV + explicit parsed fields
    # CommandLine is now explicitly forwarded so SP-001 / PS-003 rules work reliably
    event_for_detector = {
        **doc,
        **payload.get("_kv", {}),
        "EventID":     payload.get("EventID",     doc.get("event_id", "")),
        "IpAddress":   payload.get("IpAddress",   doc.get("src_ip", "")),
        "LogonType":   payload.get("LogonType",   ""),
        "ProcessName": payload.get("ProcessName", doc.get("process", "")),
        "CommandLine": payload.get("CommandLine", ""),   # ← new explicit field
        "raw_message": payload.get("raw_message", ""),
    }

    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        logger.warning(
            f"[DETECTION] {len(alerts)} alert(s) from event "
            f"{doc.get('event_id')} | host={doc.get('host')}"
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | "
        f"alerts={len(alerts)} | id={normalized.id[:8]}"
    )

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "alerts":     len(alerts),
        "alert_ids":  [a.rule_id for a in alerts],
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
    if user:       must.append({"wildcard": {"user":       {"value": f"*{user}*",        "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":       {"value": f"*{host}*",        "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*","case_insensitive": True}}})
    if since:      must.append({"range":    {"timestamp":  {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    res   = await es.search(
        index = get_index(),
        query = query,
        sort  = [{"timestamp": {"order": "desc"}}],
        size  = limit,
    )
    return [LogResponse(**hit["_source"]) for hit in res["hits"]["hits"]]


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
    """Return detected threat alerts, newest first."""
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
    return [hit["_source"] for hit in res["hits"]["hits"]]


# ── GET /alerts/summary ────────────────────────────────────────────────────────

@app.get("/alerts/summary", tags=["Detection"])
async def alerts_summary():
    """Aggregated alert counts by severity, tactic, rule, and host."""
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
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    print("[DEBUG RAW] ct:", request.headers.get("content-type"))
    print("[DEBUG RAW] body:", parsed)
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 2 (Threat Detection)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 2",
    description = "NXLog → FastAPI → Elasticsearch + Threat Detection",
    version     = "5.1.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"


# ── Rate limiter ───────────────────────────────────────────────────────────────
# NXLog traffic is ALWAYS exempt — it sends many events rapidly and must never
# be rate-limited or the detection pipeline stalls.
# All other clients (curl, browser, scripts) are limited to 200 req / 60s.

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
    """
    Returns True if the request is coming from NXLog.
    NXLog CE om_http sets User-Agent to something like:
      "nxlog" / "NXLog" / "nxlog-ce/3.2.2329"
    We also check a custom header as fallback (set in nxlog.conf if needed).
    """
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


# ── Alert indexer ──────────────────────────────────────────────────────────────

async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    es = get_es()
    try:
        exists = await es.indices.exists(index=ALERTS_INDEX)
        if not exists:
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp":   {"type": "date"},
                        "severity":    {"type": "keyword"},
                        "rule_id":     {"type": "keyword"},
                        "technique":   {"type": "keyword"},
                        "tactic":      {"type": "keyword"},
                        "host":        {"type": "keyword"},
                        "user":        {"type": "keyword"},
                        "src_ip":      {"type": "ip", "ignore_malformed": True},
                        "title":       {"type": "text"},
                        "description": {"type": "text"},
                    }
                }
            )
    except Exception as e:
        logger.error(f"[ALERTS INDEX] Could not create index: {e}")

    for alert in alerts:
        try:
            await es.index(index=ALERTS_INDEX, document=alert.to_dict())
        except Exception as e:
            logger.error(f"[ALERT INDEX ERROR] {alert.rule_id}: {e}")


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    """
    Ingest one log. Accepts raw NXLog JSON or wrapped {source, payload} format.

    Rate limiting:
      - NXLog (detected via User-Agent)  → ALWAYS allowed, no limit
      - All other clients                → 200 req / 60s per IP
    """
    # ── Rate limit — exempt NXLog entirely ────────────────────────────────────
    if not _is_nxlog(request):
        if not _check_rate_limit(_get_client_ip(request)):
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
            )

    raw_body     = await request.body()
    content_type = request.headers.get("content-type", "")

    logger.info(f"[RAW] ct={content_type} ua={request.headers.get('user-agent','')} body={raw_body[:200]}")

    # ── Parse ─────────────────────────────────────────────────────────────────
    try:
        source, payload = _parse_body(content_type, raw_body)
    except Exception as e:
        return JSONResponse(status_code=400,
            content={"success": False, "error": f"Parse error: {e}"})

    # ── Normalize ─────────────────────────────────────────────────────────────
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"})

    # ── Index into ES ─────────────────────────────────────────────────────────
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"})

    # ── Detect ────────────────────────────────────────────────────────────────
    event_for_detector = {
        **doc,
        **payload.get("_kv", {}),
        "EventID":     payload.get("EventID",     doc.get("event_id", "")),
        "IpAddress":   payload.get("IpAddress",   doc.get("src_ip", "")),
        "LogonType":   payload.get("LogonType",   ""),
        "ProcessName": payload.get("ProcessName", doc.get("process", "")),
        "CommandLine": payload.get("CommandLine", ""),
        "raw_message": payload.get("raw_message", ""),
    }

    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        logger.warning(
            f"[DETECTION] {len(alerts)} alert(s) | "
            f"rules={[a.rule_id for a in alerts]} | host={doc.get('host')}"
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | "
        f"nxlog={_is_nxlog(request)} | alerts={len(alerts)} | id={normalized.id[:8]}"
    )

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "alerts":     len(alerts),
        "alert_ids":  [a.rule_id for a in alerts],
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    # Bulk endpoint also exempts NXLog from rate limiting
    if not _is_nxlog(request):
        if not _check_rate_limit(_get_client_ip(request)):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
    if user:       must.append({"wildcard": {"user":            {"value": f"*{user}*",        "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":            {"value": f"*{host}*",        "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*",     "case_insensitive": True}}})
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
    return [hit["_source"] for hit in res["hits"]["hits"]]


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
                        "source": "doc['ingested_at'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                    }
                }
            },
        },
    )
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    logger.info(f"[DEBUG RAW] ct={request.headers.get('content-type')} ua={request.headers.get('user-agent')}")
    logger.info(f"[DEBUG RAW] body={json.dumps(parsed, default=str)[:500]}")
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
"""
main.py — SOC Backend Phase 2 (Threat Detection)
Run:  uvicorn main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import logging
import json
import re
import time
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc")

from db import connect_db, close_db, get_es, get_index, reset_index
from models import BulkIngestionResponse, LogResponse, EventType, LogSource
from normalizer import normalize
from detector import detect, Alert


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title       = "SOC Backend — Phase 2",
    description = "NXLog → FastAPI → Elasticsearch + Threat Detection",
    version     = "5.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALERTS_INDEX = "soc-alerts"


# ── Rate limiter ───────────────────────────────────────────────────────────────

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
# PARSER — module-level constants (compiled once at import, reused per request)
# ═══════════════════════════════════════════════════════════════════════════════

_RE_KV = re.compile(r'([\w\-]+)="([^"]*)"')
_RE_EVENTID = re.compile(r'\bEventID=(\d+)', re.IGNORECASE)
_RE_IPV4 = re.compile(
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

_USER_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName", "UserName")
_IP_FIELDS   = ("IpAddress", "SourceAddress", "SourceNetworkAddress")
_PROC_FIELDS = ("NewProcessName", "ProcessName", "Application")


def _parse_syslog_string(raw: str) -> dict:
    """
    Parse an NXLog CE syslog message into a structured dict for the normalizer.
    Never raises — always returns a dict (may be partial on malformed input).
    """
    payload: dict = {"raw_message": raw}

    try:
        # ── Step 1: Extract ALL Key="Value" pairs ─────────────────────────────
        kv: dict[str, str] = dict(_RE_KV.findall(raw))
        payload["_kv"] = kv

        # ── Step 2: EventID ───────────────────────────────────────────────────
        event_id = kv.get("EventID", "").strip()
        if not event_id:
            m = _RE_EVENTID.search(raw)
            if m:
                event_id = m.group(1)
        if event_id:
            payload["EventID"] = event_id

        # ── Step 3: Hostname ──────────────────────────────────────────────────
        hostname = (kv.get("Hostname") or kv.get("Computer") or "").strip()
        if not hostname:
            parts = raw.split()
            if len(parts) >= 4 and parts[3] not in ("-", ""):
                hostname = parts[3]
        if hostname:
            payload["Hostname"] = hostname

        # ── Step 4: Username ──────────────────────────────────────────────────
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

        # ── Step 5: Source IP address ─────────────────────────────────────────
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

        # ── Step 6: Process name ──────────────────────────────────────────────
        for field in _PROC_FIELDS:
            v = kv.get(field, "").strip()
            if v and v != "-":
                payload["ProcessName"] = v
                break

        # ── Step 7: CommandLine ───────────────────────────────────────────────
        cmdline = kv.get("CommandLine", "").strip()
        if not cmdline:
            m = re.search(r'CommandLine="([^"]*)"', raw)
            if m:
                cmdline = m.group(1)
        if cmdline:
            payload["CommandLine"] = cmdline

        # ── Step 8: LogonType ─────────────────────────────────────────────────
        logon_raw = (kv.get("LogonType") or kv.get("Logon-Type") or "").strip()
        if logon_raw:
            payload["LogonType"] = str(int(logon_raw)) if logon_raw.isdigit() else logon_raw

    except Exception as exc:
        logger.error(
            f"[PARSE SYSLOG] Unexpected error: {exc!r} "
            f"| raw[:200]={raw[:200]!r}"
        )

    logger.info(
        "[PARSE SYSLOG] "
        f"EventID={payload.get('EventID')} "
        f"user={payload.get('TargetUserName')} "
        f"host={payload.get('Hostname')} "
        f"ip={payload.get('IpAddress')} "
        f"proc={payload.get('ProcessName')} "
        f"cmdline={'yes' if payload.get('CommandLine') else 'no'} "
        f"logon_type={payload.get('LogonType')}"
    )
    return payload


# ── Alert indexer ──────────────────────────────────────────────────────────────

async def _index_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        return
    es = get_es()

    try:
        exists = await es.indices.exists(index=ALERTS_INDEX)
        if not exists:
            await es.indices.create(
                index    = ALERTS_INDEX,
                mappings = {
                    "properties": {
                        "timestamp":   {"type": "date"},
                        "severity":    {"type": "keyword"},
                        "rule_id":     {"type": "keyword"},
                        "technique":   {"type": "keyword"},
                        "tactic":      {"type": "keyword"},
                        "host":        {"type": "keyword"},
                        "user":        {"type": "keyword"},
                        "src_ip":      {"type": "ip", "ignore_malformed": True},
                        "title":       {"type": "text"},
                        "description": {"type": "text"},
                    }
                }
            )
    except Exception as e:
        logger.error(f"[ALERTS INDEX] Could not create index: {e}")

    for alert in alerts:
        try:
            await es.index(index=ALERTS_INDEX, document=alert.to_dict())
        except Exception as e:
            logger.error(f"[ALERT INDEX ERROR] {alert.rule_id}: {e}")


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    es   = get_es()
    ping = await es.ping()
    return {
        "status":    "ok" if ping else "es_unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /logs ─────────────────────────────────────────────────────────────────

@app.post("/logs", tags=["Ingestion"])
async def ingest_log(request: Request):
    """
    Ingest one log. Accepts raw NXLog JSON or wrapped {source, payload} format.
    Never returns 422 — bad events return {success: false, error: ...} with 200
    so NXLog doesn't retry endlessly on normalization failures.
    """
    user_agent = request.headers.get("user-agent", "")
    if "nxlog" not in user_agent.lower():
        if not _check_rate_limit(_get_client_ip(request)):
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": "Rate limit exceeded — 200 req/60s"}
            )

    # ── Parse body ────────────────────────────────────────────────────────────
    try:
        raw_body = await request.body()
        data     = json.loads(raw_body)
    except Exception as e:
        logger.error(f"[PARSE ERROR] Could not parse JSON body: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": f"Invalid JSON: {e}"}
        )

    # ── Auto-detect format ────────────────────────────────────────────────────
    if "payload" not in data:
        # FORMAT A: NXLog sent raw flat JSON — wrap it
        source  = "nxlog"
        payload = data
        logger.info(
            f"[INGEST] Format A (raw NXLog) — "
            f"EventID={data.get('EventID')} Host={data.get('Hostname')}"
        )
    else:
        # FORMAT B: already wrapped — use as-is
        source  = data.get("source", "nxlog")
        payload = data.get("payload", {})
        logger.info(
            f"[INGEST] Format B (wrapped) — "
            f"source={source} EventID={payload.get('EventID')}"
        )

    # ── Normalize ─────────────────────────────────────────────────────────────
    try:
        normalized = normalize(LogSource(source), payload)
    except Exception as e:
        logger.error(f"[NORMALIZE ERROR] {e}")
        logger.error(f"[NORMALIZE ERROR] source={source}")
        logger.error(f"[NORMALIZE ERROR] payload={json.dumps(payload, default=str)[:1000]}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Normalization failed: {e}"}
        )

    # ── Index to Elasticsearch ────────────────────────────────────────────────
    try:
        doc = _prep_doc(normalized)
        es  = get_es()
        await es.index(index=get_index(), id=normalized.id, document=doc)
    except Exception as e:
        logger.error(f"[ES ERROR] {e}")
        return JSONResponse(
            status_code=200,
            content={"success": False, "error": f"Elasticsearch error: {e}"}
        )

    # ── Threat detection ──────────────────────────────────────────────────────
    event_for_detector = {
        **doc,
        **payload.get("_kv", {}),
        "EventID":     payload.get("EventID",     doc.get("event_id", "")),
        "IpAddress":   payload.get("IpAddress",   doc.get("src_ip", "")),
        "LogonType":   payload.get("LogonType",   ""),
        "ProcessName": payload.get("ProcessName", doc.get("process", "")),
        "CommandLine": payload.get("CommandLine", ""),
        "raw_message": payload.get("raw_message", ""),
    }

    alerts = detect(event_for_detector)

    if alerts:
        await _index_alerts(alerts)
        logger.warning(
            f"[DETECTION] {len(alerts)} alert(s) from event "
            f"{doc.get('event_id')} | host={doc.get('host')}"
        )

    logger.info(
        f"[OK] {normalized.event_type.value} | "
        f"user={normalized.user} | host={normalized.host} | "
        f"alerts={len(alerts)} | id={normalized.id[:8]}"
    )

    return {
        "success":    True,
        "log_id":     normalized.id,
        "event_type": normalized.event_type.value,
        "alerts":     len(alerts),
        "alert_ids":  [a.rule_id for a in alerts],
        "message":    f"Indexed {normalized.event_type.value} [{normalized.id[:8]}...]",
    }


# ── POST /logs/bulk ────────────────────────────────────────────────────────────

@app.post("/logs/bulk", response_model=BulkIngestionResponse, status_code=201, tags=["Ingestion"])
async def ingest_bulk(request: Request):
    if not _check_rate_limit(_get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        data  = await request.json()
        items = data.get("logs", [])
        if not items:
            raise ValueError("'logs' array is empty or missing")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    accepted_ids: list[str] = []
    errors:       list[str] = []
    bulk_ops:     list      = []

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
    if user:       must.append({"wildcard": {"user":       {"value": f"*{user}*",         "case_insensitive": True}}})
    if host:       must.append({"wildcard": {"host":       {"value": f"*{host}*",         "case_insensitive": True}}})
    if process:    must.append({"wildcard": {"process.keyword": {"value": f"*{process}*", "case_insensitive": True}}})
    if since:      must.append({"range":    {"timestamp":  {"gte": since.isoformat()}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    es    = get_es()
    res   = await es.search(
        index = get_index(),
        query = query,
        sort  = [{"timestamp": {"order": "desc"}}],
        size  = limit,
    )
    return [LogResponse(**hit["_source"]) for hit in res["hits"]["hits"]]


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
    """Return detected threat alerts, newest first."""
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
    return [hit["_source"] for hit in res["hits"]["hits"]]


# ── GET /alerts/summary ────────────────────────────────────────────────────────

@app.get("/alerts/summary", tags=["Detection"])
async def alerts_summary():
    """Aggregated alert counts by severity, tactic, rule, and host."""
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
        return {
            "total": 0, "by_severity": {}, "by_tactic": {},
            "by_rule": {}, "by_host": {}, "timeline": []
        }

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
    aggs     = res["aggregations"]
    by_type  = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
    by_host  = {b["key"]: b["doc_count"] for b in aggs["by_host"]["buckets"]}
    timeline = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in aggs["timeline"]["buckets"] if b["doc_count"] > 0
    ]
    return {
        "total":          res["hits"]["total"]["value"],
        "by_type":        by_type,
        "by_host":        by_host,
        "timeline":       timeline,
        "avg_latency_ms": round(aggs["avg_latency_ms"].get("value") or 0, 2),
    }


# ── GET /logs/{id} ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=LogResponse, tags=["Query"])
async def get_log(log_id: str):
    es = get_es()
    try:
        res = await es.get(index=get_index(), id=log_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")
    return LogResponse(**res["_source"])


# ── POST /debug/raw ────────────────────────────────────────────────────────────

@app.post("/debug/raw", tags=["Debug"])
async def debug_raw(request: Request):
    body = await request.body()
    try:    parsed = json.loads(body)
    except: parsed = body.decode(errors="replace")
    print("[DEBUG RAW] ct:", request.headers.get("content-type"))
    print("[DEBUG RAW] body:", parsed)
    return {"received": parsed, "size_bytes": len(body)}


# ── POST /admin/reset-index ────────────────────────────────────────────────────

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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
