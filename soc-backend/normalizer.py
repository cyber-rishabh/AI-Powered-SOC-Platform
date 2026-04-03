"""
normalizer.py — bulletproof NXLog CE field handling.

NXLog CE sends EVERYTHING as strings:
  "EventID": "4625"      not  4625
  "ProcessId": "1234"    not  1234
  "ProcessId": ""        empty string
  "ProcessId": None      missing entirely

Every int conversion is wrapped in _safe_int().
Every field access uses .get() with a default.
Normalizer NEVER raises — worst case returns EventType.UNKNOWN.
"""

import re
import uuid
from datetime import datetime, timezone
from models import NormalizedLog, EventType, LogSource


SYSMON_EVENT_MAP = {
    1:  EventType.PROCESS_EXEC,
    3:  EventType.NETWORK_CONN,
    11: EventType.FILE_CREATE,
}

WINDOWS_EVENT_MAP = {
    4625: EventType.LOGIN_FAIL,
    4624: EventType.LOGIN_SUCCESS,
    4688: EventType.PROCESS_EXEC,
}


# ── Safe helpers ──────────────────────────────────────────────────────────────

def _safe_int(val, default: int = 0) -> int:
    """
    Convert anything NXLog might send to int without crashing.
    Handles: None, "", "4625", 4625, "0x1234", "  42  "
    """
    if val is None:
        return default
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return default
    try:
        # handle hex strings like "0x1a2b"
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))   # float() first handles "4625.0"
    except (ValueError, TypeError):
        return default


def _safe_str(val) -> str | None:
    """Return stripped string or None if empty/None."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _parse_ts(raw) -> datetime:
    """
    Parse timestamp — handles all formats NXLog CE produces:
      "2024-01-15 10:20:00"       (space separator, no tz)
      "2024-01-15T10:20:00Z"      (ISO with Z)
      "2024-01-15T10:20:00+00:00" (ISO with offset)
    Falls back to utcnow() if unparseable — never raises.
    """
    if not raw:
        return datetime.now(timezone.utc)
    s = str(raw).strip()
    # NXLog CE uses space instead of T between date and time
    s = s.replace(" ", "T", 1)
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        # If no timezone info, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _extract_username(text: str) -> str | None:
    m = re.search(r"Account Name:\s*([^\s\r\n]+)", text)
    return m.group(1) if m else None


def _normalise_nxlog_fields(payload: dict) -> dict:
    """
    Remap NXLog CE field names → names our parsers expect.
    Non-destructive (works on a copy).
    """
    p = dict(payload)

    # NXLog CE timestamp field is "EventTime", not "TimeCreated" or "UtcTime"
    et = p.get("EventTime")
    if et:
        p.setdefault("TimeCreated", et)
        p.setdefault("UtcTime", et)

    # NXLog CE host field is "Hostname", not "Computer"
    hn = p.get("Hostname")
    if hn:
        p.setdefault("Computer", hn)

    return p


# ── Sysmon parser ─────────────────────────────────────────────────────────────

def normalize_sysmon(payload: dict) -> NormalizedLog:
    event_id   = _safe_int(payload.get("EventID"))
    event_type = SYSMON_EVENT_MAP.get(event_id, EventType.UNKNOWN)

    # NXLog CE sends fields flat; raw Sysmon XML nests under EventData.
    # Using payload as fallback for "ed" handles both cases correctly.
    ed = payload.get("EventData") or payload

    return NormalizedLog(
        id          = str(uuid.uuid4()),
        timestamp   = _parse_ts(
                        payload.get("UtcTime")
                        or payload.get("EventTime")
                        or payload.get("@timestamp")
                      ),
        event_type  = event_type,
        source      = LogSource.SYSMON,
        user        = _safe_str(ed.get("User") or ed.get("SubjectUserName")),
        host        = _safe_str(
                        payload.get("Computer")
                        or payload.get("Hostname")
                        or payload.get("hostname")
                      ),
        process     = _safe_str(ed.get("Image") or ed.get("ProcessName")),
        process_id  = _safe_int(ed.get("ProcessId")) or None,
        parent_proc = _safe_str(ed.get("ParentImage")),
        ip_src      = _safe_str(ed.get("SourceIp")),
        ip_dst      = _safe_str(ed.get("DestinationIp")),
        port_dst    = _safe_int(ed.get("DestinationPort")) or None,
        raw         = payload,
        tags        = ["sysmon", f"event_id:{event_id}"],
    )


# ── Windows Security parser ───────────────────────────────────────────────────

def normalize_windows(payload: dict) -> NormalizedLog:
    event_id   = _safe_int(payload.get("EventID"))
    event_type = WINDOWS_EVENT_MAP.get(event_id, EventType.UNKNOWN)
    raw_msg    = _safe_str(payload.get("Message")) or ""

    user = _safe_str(
        payload.get("SubjectUserName")
        or payload.get("TargetUserName")
        or _extract_username(raw_msg)
    )

    return NormalizedLog(
        id         = str(uuid.uuid4()),
        timestamp  = _parse_ts(
                       payload.get("TimeCreated")
                       or payload.get("EventTime")
                       or payload.get("@timestamp")
                     ),
        event_type = event_type,
        source     = LogSource.WINDOWS,
        user       = user,
        host       = _safe_str(
                       payload.get("WorkstationName")
                       or payload.get("Computer")
                       or payload.get("Hostname")
                     ),
        process    = _safe_str(payload.get("ProcessName")),
        process_id = _safe_int(payload.get("ProcessId")) or None,
        raw        = payload,
        tags       = ["windows", f"event_id:{event_id}"],
    )


# ── NXLog CE dispatcher ───────────────────────────────────────────────────────

def normalize_nxlog(payload: dict) -> NormalizedLog:
    """
    NXLog CE with xm_json produces flat JSON with string values.
    Actual example of what arrives:

    {
      "EventTime":       "2024-01-15 10:20:00",
      "Hostname":        "WIN10-LAB",
      "EventID":         "4625",          ← STRING not int
      "SourceName":      "Microsoft-Windows-Security-Auditing",
      "Channel":         "Security",
      "TargetUserName":  "admin",
      "WorkstationName": "WIN10-LAB",
      "ProcessId":       "4321"           ← STRING not int
    }

    Sysmon (EventID 1 = Process Create):
    {
      "EventTime":   "2024-01-15 10:26:00",
      "Hostname":    "WIN10-LAB",
      "EventID":     "1",
      "SourceName":  "Microsoft-Windows-Sysmon",
      "Channel":     "Microsoft-Windows-Sysmon/Operational",
      "Image":       "C:\\Windows\\System32\\cmd.exe",
      "User":        "LAB\\admin",
      "ProcessId":   "4321",
      "ParentImage": "C:\\Windows\\explorer.exe"
    }
    """
    p = _normalise_nxlog_fields(payload)

    source_name = str(p.get("SourceName", "")).lower()
    channel     = str(p.get("Channel", "")).lower()
    event_id    = _safe_int(p.get("EventID"))

    is_sysmon = (
        "sysmon" in channel
        or "sysmon" in source_name
        or event_id in SYSMON_EVENT_MAP
    )

    if is_sysmon:
        log = normalize_sysmon(p)
    else:
        log = normalize_windows(p)

    log.source = LogSource.NXLOG
    return log


# ── Entry point ───────────────────────────────────────────────────────────────

def normalize(source: LogSource, payload: dict) -> NormalizedLog:
    return {
        LogSource.SYSMON:  normalize_sysmon,
        LogSource.WINDOWS: normalize_windows,
        LogSource.NXLOG:   normalize_nxlog,
    }[source](payload)
"""
normalizer.py — bulletproof NXLog CE field handling.

NXLog CE sends EVERYTHING as strings:
  "EventID": "4625"      not  4625
  "ProcessId": "1234"    not  1234
  "ProcessId": ""        empty string
  "ProcessId": None      missing entirely

Every int conversion is wrapped in _safe_int().
Every field access uses .get() with a default.
Normalizer NEVER raises — worst case returns EventType.UNKNOWN.
"""

import re
import uuid
from datetime import datetime, timezone
from models import NormalizedLog, EventType, LogSource


SYSMON_EVENT_MAP = {
    1:  EventType.PROCESS_EXEC,
    3:  EventType.NETWORK_CONN,
    11: EventType.FILE_CREATE,
}

WINDOWS_EVENT_MAP = {
    4625: EventType.LOGIN_FAIL,
    4624: EventType.LOGIN_SUCCESS,
    4688: EventType.PROCESS_EXEC,
}


# ── Safe helpers ──────────────────────────────────────────────────────────────

def _safe_int(val, default: int = 0) -> int:
    """
    Convert anything NXLog might send to int without crashing.
    Handles: None, "", "4625", 4625, "0x1234", "  42  "
    """
    if val is None:
        return default
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return default
    try:
        # handle hex strings like "0x1a2b"
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))   # float() first handles "4625.0"
    except (ValueError, TypeError):
        return default


def _safe_str(val) -> str | None:
    """Return stripped string or None if empty/None."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _parse_ts(raw) -> datetime:
    """
    Parse timestamp — handles all formats NXLog CE produces:
      "2024-01-15 10:20:00"       (space separator, no tz)
      "2024-01-15T10:20:00Z"      (ISO with Z)
      "2024-01-15T10:20:00+00:00" (ISO with offset)
    Falls back to utcnow() if unparseable — never raises.
    """
    if not raw:
        return datetime.now(timezone.utc)
    s = str(raw).strip()
    # NXLog CE uses space instead of T between date and time
    s = s.replace(" ", "T", 1)
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        # If no timezone info, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _extract_username(text: str) -> str | None:
    m = re.search(r"Account Name:\s*([^\s\r\n]+)", text)
    return m.group(1) if m else None


def _normalise_nxlog_fields(payload: dict) -> dict:
    """
    Remap NXLog CE field names → names our parsers expect.
    Non-destructive (works on a copy).
    """
    p = dict(payload)

    # NXLog CE timestamp field is "EventTime", not "TimeCreated" or "UtcTime"
    et = p.get("EventTime")
    if et:
        p.setdefault("TimeCreated", et)
        p.setdefault("UtcTime", et)

    # NXLog CE host field is "Hostname", not "Computer"
    hn = p.get("Hostname")
    if hn:
        p.setdefault("Computer", hn)

    return p


# ── Sysmon parser ─────────────────────────────────────────────────────────────

def normalize_sysmon(payload: dict) -> NormalizedLog:
    event_id   = _safe_int(payload.get("EventID"))
    event_type = SYSMON_EVENT_MAP.get(event_id, EventType.UNKNOWN)

    # NXLog CE sends fields flat; raw Sysmon XML nests under EventData.
    # Using payload as fallback for "ed" handles both cases correctly.
    ed = payload.get("EventData") or payload

    return NormalizedLog(
        id          = str(uuid.uuid4()),
        timestamp   = _parse_ts(
                        payload.get("UtcTime")
                        or payload.get("EventTime")
                        or payload.get("@timestamp")
                      ),
        event_type  = event_type,
        source      = LogSource.SYSMON,
        user        = _safe_str(ed.get("User") or ed.get("SubjectUserName")),
        host        = _safe_str(
                        payload.get("Computer")
                        or payload.get("Hostname")
                        or payload.get("hostname")
                      ),
        process     = _safe_str(ed.get("Image") or ed.get("ProcessName")),
        process_id  = _safe_int(ed.get("ProcessId")) or None,
        parent_proc = _safe_str(ed.get("ParentImage")),
        ip_src      = _safe_str(ed.get("SourceIp")),
        ip_dst      = _safe_str(ed.get("DestinationIp")),
        port_dst    = _safe_int(ed.get("DestinationPort")) or None,
        raw         = payload,
        tags        = ["sysmon", f"event_id:{event_id}"],
    )


# ── Windows Security parser ───────────────────────────────────────────────────

def normalize_windows(payload: dict) -> NormalizedLog:
    event_id   = _safe_int(payload.get("EventID"))
    event_type = WINDOWS_EVENT_MAP.get(event_id, EventType.UNKNOWN)
    raw_msg    = _safe_str(payload.get("Message")) or ""

    user = _safe_str(
        payload.get("SubjectUserName")
        or payload.get("TargetUserName")
        or _extract_username(raw_msg)
    )

    return NormalizedLog(
        id         = str(uuid.uuid4()),
        timestamp  = _parse_ts(
                       payload.get("TimeCreated")
                       or payload.get("EventTime")
                       or payload.get("@timestamp")
                     ),
        event_type = event_type,
        source     = LogSource.WINDOWS,
        user       = user,
        host       = _safe_str(
                       payload.get("WorkstationName")
                       or payload.get("Computer")
                       or payload.get("Hostname")
                     ),
        process    = _safe_str(payload.get("ProcessName")),
        process_id = _safe_int(payload.get("ProcessId")) or None,
        raw        = payload,
        tags       = ["windows", f"event_id:{event_id}"],
    )


# ── NXLog CE dispatcher ───────────────────────────────────────────────────────

def normalize_nxlog(payload: dict) -> NormalizedLog:
    """
    NXLog CE with xm_json produces flat JSON with string values.
    Actual example of what arrives:

    {
      "EventTime":       "2024-01-15 10:20:00",
      "Hostname":        "WIN10-LAB",
      "EventID":         "4625",          ← STRING not int
      "SourceName":      "Microsoft-Windows-Security-Auditing",
      "Channel":         "Security",
      "TargetUserName":  "admin",
      "WorkstationName": "WIN10-LAB",
      "ProcessId":       "4321"           ← STRING not int
    }

    Sysmon (EventID 1 = Process Create):
    {
      "EventTime":   "2024-01-15 10:26:00",
      "Hostname":    "WIN10-LAB",
      "EventID":     "1",
      "SourceName":  "Microsoft-Windows-Sysmon",
      "Channel":     "Microsoft-Windows-Sysmon/Operational",
      "Image":       "C:\\Windows\\System32\\cmd.exe",
      "User":        "LAB\\admin",
      "ProcessId":   "4321",
      "ParentImage": "C:\\Windows\\explorer.exe"
    }
    """
    p = _normalise_nxlog_fields(payload)

    source_name = str(p.get("SourceName", "")).lower()
    channel     = str(p.get("Channel", "")).lower()
    event_id    = _safe_int(p.get("EventID"))

    is_sysmon = (
        "sysmon" in channel
        or "sysmon" in source_name
        or event_id in SYSMON_EVENT_MAP
    )

    if is_sysmon:
        log = normalize_sysmon(p)
    else:
        log = normalize_windows(p)

    log.source = LogSource.NXLOG
    return log


# ── Entry point ───────────────────────────────────────────────────────────────

def normalize(source: LogSource, payload: dict) -> NormalizedLog:
    return {
        LogSource.SYSMON:  normalize_sysmon,
        LogSource.WINDOWS: normalize_windows,
        LogSource.NXLOG:   normalize_nxlog,
    }[source](payload)
