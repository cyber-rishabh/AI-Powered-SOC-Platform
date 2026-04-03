"""
detector.py — SOC Threat Detection Engine
==========================================
Runs on every ingested log. Detects:

  BRUTE FORCE
    - 5+ failed logins (4625) from same IP in 2 minutes
    - 10+ failed logins from same user in 5 minutes

  CREDENTIAL STUFFING
    - 3+ failed logins across 3+ different usernames from same IP in 5 min

  PRIVILEGE ESCALATION
    - Special privileges assigned (4672) immediately after logon (4624)
    - Sensitive privilege use (4673)
    - User added to privileged group (4728/4732/4756)

  LATERAL MOVEMENT
    - Network logon (type 3) to multiple hosts from same user in 10 min
    - Pass-the-hash indicators (4624 logon type 3 with NTLM)

  PERSISTENCE
    - New service installed (7045)
    - New user account created (4720)
    - Scheduled task created (Sysmon EventID 1 with schtasks.exe)

  DEFENSE EVASION
    - Audit log cleared (1102)
    - Process injection indicators (Sysmon EventID 8)

  SUSPICIOUS PROCESS
    - Known LOLBins launched (powershell, wscript, mshta, regsvr32, etc.)
    - Encoded PowerShell commands (-enc / -encodedcommand)
    - Process launched from temp/user directories

Each detection produces an Alert with:
  - severity: critical / high / medium / low
  - tactic: MITRE ATT&CK tactic name
  - technique: MITRE ATT&CK technique ID
  - description: human-readable explanation
  - evidence: raw field values that triggered it
"""

from __future__ import annotations

import re
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("soc.detector")


# ── Alert dataclass ────────────────────────────────────────────────────────────

@dataclass
class Alert:
    rule_id:     str
    severity:    str          # critical | high | medium | low
    tactic:      str          # MITRE ATT&CK tactic
    technique:   str          # MITRE ATT&CK technique ID
    title:       str
    description: str
    host:        str
    user:        Optional[str]
    src_ip:      Optional[str]
    event_ids:   list[str]
    evidence:    dict
    timestamp:   datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "severity":    self.severity,
            "tactic":      self.tactic,
            "technique":   self.technique,
            "title":       self.title,
            "description": self.description,
            "host":        self.host,
            "user":        self.user,
            "src_ip":      self.src_ip,
            "event_ids":   self.event_ids,
            "evidence":    self.evidence,
            "timestamp":   self.timestamp.isoformat(),
        }


# ── Sliding window counter ─────────────────────────────────────────────────────

class _Window:
    """
    Lightweight sliding-window event store.
    Stores (timestamp, metadata) tuples per key.
    Automatically evicts entries older than max_age_seconds.
    Accepts an optional event_time so replayed/ingested events use their
    own timestamp rather than wall-clock time.
    """

    def __init__(self, max_age_seconds: int):
        self._max_age = max_age_seconds
        self._store: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    def add(self, key: str, meta: dict, event_time: Optional[datetime] = None) -> None:
        ts = event_time or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        self._store[key].append((ts, meta))
        self._evict(key, ts)

    def count(self, key: str, ref_time: Optional[datetime] = None) -> int:
        self._evict(key, ref_time or datetime.now(timezone.utc))
        return len(self._store[key])

    def entries(self, key: str, ref_time: Optional[datetime] = None) -> list[tuple[datetime, dict]]:
        self._evict(key, ref_time or datetime.now(timezone.utc))
        return list(self._store[key])

    def unique_values(self, key: str, field: str, ref_time: Optional[datetime] = None) -> set:
        # None values are explicitly filtered to keep sets clean
        return {
            m.get(field)
            for _, m in self.entries(key, ref_time)
            if m.get(field) is not None
        }

    def _evict(self, key: str, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._max_age)
        self._store[key] = [(t, m) for t, m in self._store[key] if t > cutoff]


# ── Alert deduplication cache ──────────────────────────────────────────────────

class _DedupeCache:
    """
    Suppresses repeated alerts for the same rule+key within a cooldown window.
    Prevents alert flooding while still re-alerting if the behaviour resumes
    after the cooldown expires.

    Accepts event_time so that replayed/batch-ingested logs deduplicate
    correctly against each other rather than against wall-clock time.
    """

    def __init__(self, cooldown_seconds: int = 300):
        self._cooldown = cooldown_seconds
        self._seen: dict[str, datetime] = {}

    def should_fire(self, rule_id: str, key: str, event_time: Optional[datetime] = None) -> bool:
        dedup_key = f"{rule_id}:{key}"
        now = event_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        last = self._seen.get(dedup_key)
        if last and (now - last).total_seconds() < self._cooldown:
            logger.debug(
                f"[DEDUP] Suppressed {rule_id} for key='{key}' "
                f"(cooldown {self._cooldown}s, last fired {last.isoformat()})"
            )
            return False
        self._seen[dedup_key] = now
        return True


# ── Detection state (in-memory sliding windows) ────────────────────────────────

_failed_logins_by_ip   = _Window(120)   # 2 min  — brute force by IP
_failed_logins_by_user = _Window(300)   # 5 min  — brute force by user
_logins_by_ip          = _Window(300)   # 5 min  — credential stuffing
_network_logons        = _Window(600)   # 10 min — lateral movement
_recent_logons         = _Window(60)    # 1 min  — priv esc: logon → 4672

_dedupe = _DedupeCache(cooldown_seconds=300)


# ── MITRE reference table ──────────────────────────────────────────────────────

_LOLBINS = {
    "powershell.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe",
    "msiexec.exe", "installutil.exe",
    "cmstp.exe", "odbcconf.exe",
    "ieexec.exe", "msconfig.exe",
    "schtasks.exe", "at.exe",
    "psexec.exe", "psexesvc.exe",
}

_PRIVILEGED_GROUPS = {
    "512",  # Domain Admins
    "519",  # Enterprise Admins
    "544",  # Administrators
    "551",  # Backup Operators
    "555",  # Remote Desktop Users (lateral movement risk)
}

_SENSITIVE_PRIVILEGES = {
    "SeDebugPrivilege",       # process injection
    "SeTcbPrivilege",         # act as OS
    "SeLoadDriverPrivilege",  # load kernel drivers
    "SeImpersonatePrivilege", # token impersonation
    "SeTakeOwnershipPrivilege",
}

_SUSPICIOUS_PATHS = (
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\",
    r"\\programdata\\",
    r"\\users\\public\\",
    r"\\downloads\\",
    r"\\desktop\\",
)


# ── Public entry point ─────────────────────────────────────────────────────────

def detect(event: dict) -> list[Alert]:
    """
    Run all detection rules against one normalized log event.
    Returns a (possibly empty) list of Alert objects.
    Never raises — all exceptions are caught and logged so a single
    malformed event can never crash the pipeline.
    """
    try:
        return _detect_inner(event)
    except Exception as exc:
        logger.error(
            f"[DETECT] Unhandled exception in detect(): {exc!r} | "
            f"event_id={event.get('event_id') or event.get('EventID')!r} "
            f"host={event.get('host') or event.get('Hostname')!r}",
            exc_info=True,
        )
        return []


# ── Main detection logic ───────────────────────────────────────────────────────

def _detect_inner(event: dict) -> list[Alert]:
    """Inner detection logic — called exclusively by detect()."""
    alerts: list[Alert] = []

    # ── Field extraction with safe fallbacks ──────────────────────────────────
    event_id   = str(event.get("event_id") or event.get("EventID") or "").strip()
    # Normalize host to lowercase immediately so sliding-window keys are consistent
    host       = (event.get("host") or event.get("Hostname") or "unknown").strip().lower()
    # Normalize optional fields to None when empty so callers never deal with ""
    user       = (event.get("user") or event.get("TargetUserName") or "").strip() or None
    src_ip     = (event.get("src_ip") or event.get("IpAddress") or "").strip() or None
    process    = (event.get("process") or event.get("ProcessName") or "").lower().strip()
    logon_type = str(event.get("logon_type") or event.get("LogonType") or "").strip()
    raw        = event.get("raw_message", "") or ""

    # Prefer structured CommandLine field; fall back to raw regex extraction later
    cmdline_structured = (
        event.get("CommandLine") or event.get("command_line") or ""
    ).strip()

    # Use event timestamp for accurate sliding-window placement
    raw_ts = event.get("timestamp") or event.get("TimeCreated") or event.get("@timestamp")
    try:
        if isinstance(raw_ts, datetime):
            event_time = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        elif isinstance(raw_ts, str):
            event_time = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        else:
            event_time = datetime.now(timezone.utc)
    except (ValueError, TypeError):
        event_time = datetime.now(timezone.utc)

    # Normalise process to basename; guard against empty string
    proc_name = process.split("\\")[-1].strip() if process else ""

    logger.debug(
        f"[EVAL] event_id={event_id} user={user!r} host={host!r} "
        f"src_ip={src_ip!r} proc={proc_name!r} ts={event_time.isoformat()}"
    )

    # ── 1. BRUTE FORCE — by IP (fallback to user when src_ip is missing) ──────
    #
    # Many log sources strip the source IP (NAT, proxy, Syslog forwarder).
    # Correlate on src_ip first; fall back to user so we still catch attacks
    # that arrive without an IP field.
    bf_ip_key = src_ip or user
    if event_id == "4625" and bf_ip_key:
        _failed_logins_by_ip.add(bf_ip_key, {"user": user, "host": host}, event_time)
        count = _failed_logins_by_ip.count(bf_ip_key, event_time)
        logger.debug(
            f"[BF-IP] key={bf_ip_key!r} (src_ip={src_ip!r}) failed_count={count}"
        )

        # Check critical threshold first so high-volume events fire the right rule
        if count >= 20 and _dedupe.should_fire("BF-IP-002", bf_ip_key, event_time):
            alerts.append(Alert(
                rule_id     = "BF-IP-002",
                severity    = "critical",
                tactic      = "Credential Access",
                technique   = "T1110.001",
                title       = "Brute Force — High-Volume Attack from Single IP",
                description = (
                    f"{count} failed logins from {bf_ip_key} in 2 minutes — active attack."
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4625"],
                evidence    = {"key": bf_ip_key, "count": count},
            ))
        elif count >= 5 and _dedupe.should_fire("BF-IP-001", bf_ip_key, event_time):
            alerts.append(Alert(
                rule_id     = "BF-IP-001",
                severity    = "high",
                tactic      = "Credential Access",
                technique   = "T1110.001",
                title       = "Brute Force — Multiple Failed Logins from Single IP",
                description = (
                    f"{count} failed login attempts from {bf_ip_key} in 2 minutes. "
                    f"Targeted users: "
                    f"{_failed_logins_by_ip.unique_values(bf_ip_key, 'user', event_time)}"
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4625"],
                evidence    = {
                    "key":   bf_ip_key,
                    "count": count,
                    "users": list(
                        _failed_logins_by_ip.unique_values(bf_ip_key, "user", event_time)
                    ),
                },
            ))
        else:
            logger.debug(
                f"[BF-IP] Threshold not met or deduped: count={count} "
                f"for key={bf_ip_key!r}"
            )
    elif event_id == "4625":
        logger.debug("[BF-IP] Skipped — no src_ip or user available for correlation")

    # ── 2. BRUTE FORCE — by user ───────────────────────────────────────────────
    if event_id == "4625" and user:
        _failed_logins_by_user.add(user, {"ip": src_ip, "host": host}, event_time)
        count = _failed_logins_by_user.count(user, event_time)
        logger.debug(f"[BF-USR] user={user!r} failed_count={count}")

        if count >= 10 and _dedupe.should_fire("BF-USR-001", user, event_time):
            alerts.append(Alert(
                rule_id     = "BF-USR-001",
                severity    = "high",
                tactic      = "Credential Access",
                technique   = "T1110.001",
                title       = "Brute Force — Account Under Attack",
                description = (
                    f"Account '{user}' has {count} failed login attempts in 5 minutes "
                    f"from IPs: {_failed_logins_by_user.unique_values(user, 'ip', event_time)}"
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4625"],
                evidence    = {
                    "user":  user,
                    "count": count,
                    "ips":   list(
                        _failed_logins_by_user.unique_values(user, "ip", event_time)
                    ),
                },
            ))
        else:
            logger.debug(
                f"[BF-USR] Threshold not met or deduped: count={count} for user={user!r}"
            )

    # ── 3. CREDENTIAL STUFFING ─────────────────────────────────────────────────
    cs_key = src_ip or user   # same fallback strategy as brute-force
    if event_id == "4625" and cs_key:
        _logins_by_ip.add(cs_key, {"user": user}, event_time)
        unique_users = _logins_by_ip.unique_values(cs_key, "user", event_time)
        count_cs     = _logins_by_ip.count(cs_key, event_time)
        logger.debug(
            f"[CS] key={cs_key!r} unique_users={len(unique_users)} count={count_cs}"
        )

        if (
            len(unique_users) >= 3
            and count_cs >= 3
            and _dedupe.should_fire("CS-001", cs_key, event_time)
        ):
            alerts.append(Alert(
                rule_id     = "CS-001",
                severity    = "high",
                tactic      = "Credential Access",
                technique   = "T1110.004",
                title       = "Credential Stuffing — Multiple Usernames from Single IP",
                description = (
                    f"IP {cs_key} attempted {len(unique_users)} different usernames "
                    f"in 5 minutes: {unique_users}"
                ),
                host        = host,
                user        = None,
                src_ip      = src_ip,
                event_ids   = ["4625"],
                evidence    = {"key": cs_key, "users_tried": list(unique_users)},
            ))
        else:
            logger.debug(
                f"[CS] Threshold not met or deduped: unique_users={len(unique_users)} "
                f"count={count_cs}"
            )

    # ── 4. PRIVILEGE ESCALATION — special privileges after logon ───────────────
    if event_id == "4624" and user:
        _recent_logons.add(user, {"host": host, "logon_type": logon_type}, event_time)
        logger.debug(f"[PE-001] Recorded logon for user={user!r} on host={host!r}")

    if event_id == "4672" and user:
        recent = _recent_logons.count(user, event_time)
        logger.debug(f"[PE-001] user={user!r} recent_logons_in_window={recent}")
        if recent > 0 and _dedupe.should_fire("PE-001", user, event_time):
            alerts.append(Alert(
                rule_id     = "PE-001",
                severity    = "medium",
                tactic      = "Privilege Escalation",
                technique   = "T1078",
                title       = "Privilege Escalation — Special Privileges Assigned at Logon",
                description = (
                    f"User '{user}' received special privileges (4672) immediately "
                    f"after logging on to {host}. May indicate token manipulation."
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4624", "4672"],
                evidence    = {"user": user, "host": host},
            ))
        elif recent == 0:
            logger.debug(
                f"[PE-001] No recent 4624 in window for user={user!r} — rule not triggered"
            )

    # ── 5. PRIVILEGE ESCALATION — sensitive privilege use ─────────────────────
    if event_id == "4673":
        # Prefer structured field; fall back to raw regex
        priv = (
            event.get("PrivilegeName") or event.get("privilege_name") or ""
        ).strip()
        if not priv:
            priv_match = re.search(r'PrivilegeName="([^"]+)"', raw)
            priv = priv_match.group(1).strip() if priv_match else ""
        logger.debug(f"[PE-002] user={user!r} privilege={priv!r}")

        if priv in _SENSITIVE_PRIVILEGES and _dedupe.should_fire(
            "PE-002", f"{user}:{priv}", event_time
        ):
            alerts.append(Alert(
                rule_id     = "PE-002",
                severity    = "high",
                tactic      = "Privilege Escalation",
                technique   = "T1134",
                title       = f"Sensitive Privilege Use — {priv}",
                description = (
                    f"User '{user}' used sensitive privilege '{priv}' on {host}. "
                    f"SeDebugPrivilege/SeImpersonatePrivilege are commonly abused "
                    f"for process injection and token theft."
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = ["4673"],
                evidence    = {"privilege": priv, "user": user},
            ))
        elif priv and priv not in _SENSITIVE_PRIVILEGES:
            logger.debug(
                f"[PE-002] Privilege '{priv}' not in sensitive list — rule not triggered"
            )

    # ── 6. PRIVILEGE ESCALATION — user added to privileged group ──────────────
    if event_id in ("4728", "4732", "4756"):
        # Prefer structured fields; fall back to raw regex
        group_sid_raw = (event.get("TargetSid") or event.get("target_sid") or "").strip()
        if not group_sid_raw:
            group_match   = re.search(r'TargetSid="([^"]+)"', raw)
            group_sid_raw = group_match.group(1).strip() if group_match else ""
        group_sid = group_sid_raw.split("-")[-1] if group_sid_raw else ""

        group_name = (event.get("GroupName") or event.get("group_name") or "").strip()
        if not group_name:
            group_name_match = re.search(r'GroupName="([^"]*)"', raw)
            group_name = (
                group_name_match.group(1).strip() if group_name_match else "unknown group"
            )

        logger.debug(
            f"[PE-003] user={user!r} group={group_name!r} sid_suffix={group_sid!r}"
        )

        severity = "critical" if group_sid in _PRIVILEGED_GROUPS else "medium"
        if _dedupe.should_fire("PE-003", f"{host}:{user}:{group_name}", event_time):
            alerts.append(Alert(
                rule_id     = "PE-003",
                severity    = severity,
                tactic      = "Privilege Escalation",
                technique   = "T1098",
                title       = (
                    f"Account Added to {'Privileged ' if severity == 'critical' else ''}Group"
                ),
                description = (
                    f"User '{user}' was added to group '{group_name}' on {host}. "
                    + (
                        "This is a highly privileged group — investigate immediately."
                        if severity == "critical"
                        else ""
                    )
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = [event_id],
                evidence    = {"group": group_name, "group_sid": group_sid, "user": user},
            ))

    # ── 7. LATERAL MOVEMENT — network logon to multiple hosts ─────────────────
    if event_id == "4624" and logon_type == "3" and user:
        _network_logons.add(user, {"host": host, "ip": src_ip}, event_time)
        unique_hosts = _network_logons.unique_values(user, "host", event_time)
        logger.debug(
            f"[LM-001] user={user!r} unique_hosts={len(unique_hosts)}: {unique_hosts}"
        )

        if len(unique_hosts) >= 3 and _dedupe.should_fire("LM-001", user, event_time):
            alerts.append(Alert(
                rule_id     = "LM-001",
                severity    = "high",
                tactic      = "Lateral Movement",
                technique   = "T1021",
                title       = "Lateral Movement — Network Logons to Multiple Hosts",
                description = (
                    f"User '{user}' performed network logons (type 3) to "
                    f"{len(unique_hosts)} different hosts in 10 minutes: {unique_hosts}"
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4624"],
                evidence    = {
                    "user":       user,
                    "hosts":      list(unique_hosts),
                    "logon_type": "3 (network)",
                },
            ))
        else:
            logger.debug(
                f"[LM-001] Threshold not met or deduped: unique_hosts={len(unique_hosts)}"
            )

    # ── 8. LATERAL MOVEMENT — Pass-the-Hash ───────────────────────────────────
    if event_id == "4624" and logon_type == "3":
        # Prefer structured field; fall back to raw regex; case-insensitive comparison
        auth_pkg = (
            event.get("AuthenticationPackageName") or event.get("auth_package") or ""
        ).strip()
        if not auth_pkg:
            auth_match = re.search(r'AuthenticationPackageName="([^"]+)"', raw)
            auth_pkg   = auth_match.group(1).strip() if auth_match else ""

        logger.debug(
            f"[LM-002] user={user!r} auth_pkg={auth_pkg!r} src_ip={src_ip!r}"
        )

        # PtH: NTLM network logon with a non-machine-account username
        if (
            auth_pkg.upper() == "NTLM"
            and user
            and not user.endswith("$")
            and _dedupe.should_fire("LM-002", f"{user}:{host}", event_time)
        ):
            alerts.append(Alert(
                rule_id     = "LM-002",
                severity    = "high",
                tactic      = "Lateral Movement",
                technique   = "T1550.002",
                title       = "Pass-the-Hash Indicator — NTLM Network Logon",
                description = (
                    f"User '{user}' performed an NTLM network logon (type 3) "
                    f"to {host} from {src_ip}. NTLM network logons are a common "
                    f"indicator of Pass-the-Hash attacks."
                ),
                host        = host,
                user        = user,
                src_ip      = src_ip,
                event_ids   = ["4624"],
                evidence    = {
                    "auth_package": auth_pkg,
                    "logon_type":   "3",
                    "user":         user,
                    "src_ip":       src_ip,
                },
            ))
        elif auth_pkg.upper() != "NTLM":
            logger.debug(
                f"[LM-002] auth_pkg is not NTLM ({auth_pkg!r}) — rule not triggered"
            )

    # ── 9. PERSISTENCE — new service installed ─────────────────────────────────
    if event_id == "7045":
        # Prefer structured fields; fall back to raw regex
        svc_name = (event.get("ServiceName") or event.get("service_name") or "").strip()
        svc_path = (event.get("ImagePath") or event.get("image_path") or "").strip()
        if not svc_name:
            svc_match = re.search(r'ServiceName="([^"]+)"', raw)
            svc_name  = svc_match.group(1).strip() if svc_match else "unknown"
        if not svc_path:
            path_match = re.search(r'ImagePath="([^"]+)"', raw)
            svc_path   = path_match.group(1).strip() if path_match else ""

        severity = (
            "critical"
            if any(p in svc_path.lower() for p in _SUSPICIOUS_PATHS)
            else "high"
        )
        logger.debug(
            f"[PS-001] host={host!r} service={svc_name!r} "
            f"path={svc_path!r} severity={severity}"
        )

        if _dedupe.should_fire("PS-001", f"{host}:{svc_name}", event_time):
            alerts.append(Alert(
                rule_id     = "PS-001",
                severity    = severity,
                tactic      = "Persistence",
                technique   = "T1543.003",
                title       = "Persistence — New Service Installed",
                description = (
                    f"New Windows service '{svc_name}' installed on {host}. "
                    f"Path: {svc_path}. Services are a common persistence mechanism."
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = ["7045"],
                evidence    = {"service_name": svc_name, "service_path": svc_path},
            ))

    # ── 10. PERSISTENCE — new user account created ─────────────────────────────
    if event_id == "4720":
        new_user = (
            event.get("TargetUserName") or event.get("target_user_name") or ""
        ).strip()
        if not new_user:
            new_user_match = re.search(r'TargetUserName="([^"]+)"', raw)
            new_user = (
                new_user_match.group(1).strip() if new_user_match else "unknown"
            )
        logger.debug(
            f"[PS-002] new_user={new_user!r} created_by={user!r} host={host!r}"
        )

        if _dedupe.should_fire("PS-002", f"{host}:{new_user}", event_time):
            alerts.append(Alert(
                rule_id     = "PS-002",
                severity    = "medium",
                tactic      = "Persistence",
                technique   = "T1136.001",
                title       = "Persistence — New Local User Account Created",
                description = (
                    f"New user account '{new_user}' created on {host} by '{user}'. "
                    f"Attackers create accounts to maintain persistent access."
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = ["4720"],
                evidence    = {"new_account": new_user, "created_by": user},
            ))

    # ── 11. DEFENSE EVASION — audit log cleared ────────────────────────────────
    if event_id == "1102":
        logger.debug(f"[DE-001] Audit log cleared by user={user!r} on host={host!r}")
        if _dedupe.should_fire("DE-001", host, event_time):
            alerts.append(Alert(
                rule_id     = "DE-001",
                severity    = "critical",
                tactic      = "Defense Evasion",
                technique   = "T1070.001",
                title       = "Defense Evasion — Security Audit Log Cleared",
                description = (
                    f"The Security event log was cleared on {host} by '{user}'. "
                    f"Log clearing is a strong indicator of an attacker covering tracks."
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = ["1102"],
                evidence    = {"cleared_by": user, "host": host},
            ))

    # ── 12. SUSPICIOUS PROCESS — LOLBin execution ─────────────────────────────
    if event_id in ("4688", "1") and proc_name and proc_name in _LOLBINS:
        # Prefer structured CommandLine field; fall back to raw regex
        cmdline = cmdline_structured
        if not cmdline:
            cmd_match = re.search(r'CommandLine="([^"]+)"', raw)
            cmdline   = cmd_match.group(1).strip() if cmd_match else ""

        severity = "medium"
        title    = f"Suspicious Process — LOLBin Executed: {proc_name}"

        # Escalate for encoded PowerShell
        if proc_name in ("powershell.exe", "powershell_ise.exe"):
            if re.search(r"-e(nc(odedcommand)?)?[\s]+", cmdline, re.IGNORECASE):
                severity = "high"
                title    = "Suspicious Process — Encoded PowerShell Command"

        # Escalate for process launched from a suspicious path
        if process and any(p in process for p in _SUSPICIOUS_PATHS):
            severity = "high"

        logger.debug(
            f"[SP-001] proc={proc_name!r} user={user!r} severity={severity} "
            f"cmdline={cmdline[:100]!r}"
        )

        if _dedupe.should_fire("SP-001", f"{host}:{user}:{proc_name}", event_time):
            alerts.append(Alert(
                rule_id     = "SP-001",
                severity    = severity,
                tactic      = "Execution",
                technique   = "T1059" if "powershell" in proc_name else "T1218",
                title       = title,
                description = (
                    f"LOLBin '{proc_name}' executed on {host} by '{user}'. "
                    f"Command: {cmdline[:200] if cmdline else 'unavailable'}"
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = [event_id],
                evidence    = {
                    "process":   proc_name,
                    "cmdline":   cmdline,
                    "full_path": process,
                },
            ))

    # ── 13. SUSPICIOUS PROCESS — schtasks for persistence ─────────────────────
    if event_id in ("4688", "1") and proc_name and proc_name == "schtasks.exe":
        # Prefer structured CommandLine field; fall back to raw regex
        cmdline = cmdline_structured
        if not cmdline:
            cmd_match = re.search(r'CommandLine="([^"]+)"', raw)
            cmdline   = cmd_match.group(1).strip() if cmd_match else ""

        logger.debug(
            f"[PS-003] schtasks cmdline={cmdline[:100]!r} user={user!r} host={host!r}"
        )

        if "/create" in cmdline.lower() and _dedupe.should_fire(
            "PS-003", f"{host}:{user}", event_time
        ):
            alerts.append(Alert(
                rule_id     = "PS-003",
                severity    = "high",
                tactic      = "Persistence",
                technique   = "T1053.005",
                title       = "Persistence — Scheduled Task Created via Command Line",
                description = (
                    f"schtasks.exe /create executed on {host} by '{user}'. "
                    f"Command: {cmdline[:300]}"
                ),
                host        = host,
                user        = user,
                src_ip      = None,
                event_ids   = [event_id],
                evidence    = {"cmdline": cmdline},
            ))
        elif cmdline and "/create" not in cmdline.lower():
            logger.debug(
                f"[PS-003] schtasks executed but no /create flag — rule not triggered"
            )

    # Log all fired alerts
    for alert in alerts:
        logger.warning(
            f"[ALERT] [{alert.severity.upper()}] {alert.rule_id} — "
            f"{alert.title} | host={alert.host} user={alert.user}"
        )

    return alerts
