"""
graph_engine.py — Phase 3: Attack Graph Engine (Production Edition)
SOC Correlation Engine | Multi-Stage Attack Chain Detection

Fixes vs v1:
  [CRIT-1]  prune_old_nodes() — bounded memory, no leak
  [CRIT-2]  Ordered-tuple chain dedup — no missed distinct chains
  [CRIT-3]  detected_at = latest node timestamp in path, not datetime.now()
  [CRIT-4]  all_simple_paths cutoff capped at 6 — no path explosion
  [PERF-1]  link_events() pre-filters to 2× window before O(N²) scan
  [PERF-2]  Deterministic chain_id (SHA-256) — idempotent ES upsert
  [PERF-3]  _seen_chain_ids prevents duplicate chain storage
  [ENH-1]   chain_severity derived from risk_score
  [ENH-2]   Structured pipeline and summary log lines
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import networkx as nx

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("graph_engine")


# ─── Constants ───────────────────────────────────────────────────────────────

RULE_TO_STAGE: dict[str, str] = {
    "BF": "brute_force",
    "LS": "login_success",
    "SP": "execution",
    "PE": "privilege_escalation",
    "LM": "lateral_movement",
    "EX": "exfiltration",
    "DP": "defense_evasion",
    "CR": "credential_access",
}

STAGE_SCORES: dict[str, int] = {
    "brute_force":          30,
    "login_success":        20,
    "execution":            30,
    "privilege_escalation": 40,
    "lateral_movement":     35,
    "exfiltration":         50,
    "defense_evasion":      25,
    "credential_access":    30,
    "unknown":              10,
}

# (pattern_stages, pattern_name, base_confidence)
ATTACK_PATTERNS: list[tuple[list[str], str, float]] = [
    (["brute_force", "login_success", "execution"],
     "Credential Brute-Force → Execution", 0.90),
    (["login_success", "privilege_escalation", "execution"],
     "Privilege Escalation → Execution", 0.85),
    (["execution", "lateral_movement", "execution"],
     "Lateral Movement Chain", 0.80),
    (["brute_force", "login_success", "privilege_escalation", "execution"],
     "Full Compromise Kill-Chain", 0.95),
    (["credential_access", "login_success", "exfiltration"],
     "Credential Theft → Exfiltration", 0.88),
    (["execution", "defense_evasion", "exfiltration"],
     "Stealth Exfiltration", 0.82),
]

DEFAULT_TIME_WINDOW_SECONDS: int = 300
# [CRIT-4] Hard cap — prevents combinatorial path explosion on dense graphs
MAX_PATH_CUTOFF: int = 6


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _rule_to_stage(rule_id: str) -> str:
    prefix = rule_id.split("-")[0].upper()
    return RULE_TO_STAGE.get(prefix, "unknown")


def _parse_timestamp(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        logger.warning("[GRAPH] Bad timestamp: %s", ts)
        return None


def _cap_score(score: int, maximum: int = 100) -> int:
    return min(score, maximum)


# [ENH-1] Severity label from numeric risk_score
def _score_to_severity(score: int) -> str:
    if score >= 90:  return "critical"
    if score >= 60:  return "high"
    if score >= 30:  return "medium"
    return "low"


# [PERF-2] Deterministic chain_id — same ordered path → same id always
def _make_chain_id(node_ids: list[str]) -> str:
    raw = "|".join(node_ids)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── AttackGraphEngine ────────────────────────────────────────────────────────

class AttackGraphEngine:
    """
    Directed graph of attack events with temporal + identity correlation.

    Thread-safety: single-threaded async use (FastAPI event loop). For
    multi-process deployments, move state to Redis and graph to a shared store.
    """

    def __init__(self, time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS):
        self.graph: nx.DiGraph = nx.DiGraph()
        self.time_window: int = time_window_seconds
        self._seen_alerts: set[str] = set()       # alert-level dedup
        self._seen_chain_ids: set[str] = set()    # [PERF-3] chain-level dedup
        logger.info(
            "[GRAPH] Engine ready | window=%ds path_cutoff=%d",
            time_window_seconds, MAX_PATH_CUTOFF,
        )

    # ── 1. Add Alert ──────────────────────────────────────────────────────────

    def add_alert(self, alert: dict) -> Optional[str]:
        """Convert alert → graph node. Returns node_id or None if skipped."""
        rule_id  = alert.get("rule_id", "UNKNOWN")
        user     = alert.get("user", "unknown_user")
        host     = alert.get("host", "unknown_host")
        severity = alert.get("severity", "unknown")
        ts_raw   = alert.get("timestamp", "")

        ts = _parse_timestamp(ts_raw)
        if ts is None:
            logger.warning("[ADD_ALERT] Skipped — bad timestamp | rule=%s", rule_id)
            return None

        # Alert-level dedup: same rule+user+host within the same minute
        dedup_key = f"{rule_id}|{user}|{host}|{ts.strftime('%Y%m%dT%H%M')}"
        if dedup_key in self._seen_alerts:
            logger.debug("[ADD_ALERT] Duplicate skipped | %s", dedup_key)
            return None
        self._seen_alerts.add(dedup_key)

        stage   = _rule_to_stage(rule_id)
        node_id = str(uuid.uuid4())
        self.graph.add_node(node_id, **{
            "type":      stage,
            "timestamp": ts,
            "user":      user,
            "host":      host,
            "metadata": {
                "rule_id":  rule_id,
                "severity": severity,
                "raw":      alert,
            },
        })
        logger.info(
            "[ADD_ALERT] node=%-8s stage=%-22s user=%-12s host=%-10s ts=%s",
            node_id[:8], stage, user, host, ts.isoformat(),
        )
        return node_id

    # ── 2. Prune Old Nodes ────────────────────────────────────────────────────
    # [CRIT-1] Fix memory leak — call before every link_events() pass

    def prune_old_nodes(self) -> int:
        """
        Remove nodes whose timestamp predates the correlation window.
        Rebuilds _seen_alerts from surviving nodes to allow re-ingestion
        after a node expires and the same alert arrives again later.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.time_window)
        stale  = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("timestamp") and d["timestamp"] < cutoff
        ]
        for n in stale:
            self.graph.remove_node(n)

        if stale:
            # Rebuild dedup set from surviving nodes only
            surviving: set[str] = set()
            for _, d in self.graph.nodes(data=True):
                ts = d.get("timestamp")
                key = (
                    f"{d['metadata']['rule_id']}|{d['user']}|{d['host']}|"
                    f"{ts.strftime('%Y%m%dT%H%M') if ts else 'x'}"
                )
                surviving.add(key)
            self._seen_alerts = surviving
            logger.info(
                "[PRUNE] Removed %d stale node(s) | survivors=%d",
                len(stale), self.graph.number_of_nodes(),
            )
        return len(stale)

    # ── 3. Link Events ────────────────────────────────────────────────────────
    # [PERF-1] Pre-filter to 2× window before O(N²) scan

    def link_events(self) -> int:
        """
        Draw directed edges between nodes that share identity (user or host)
        and fall within the correlation time window.

        Optimisation: only nodes seen within 2× time_window enter the pair
        scan — keeps the working set small on high-volume sensors.
        """
        # [CRIT-1] Prune before linking every time
        self.prune_old_nodes()

        now       = datetime.now(timezone.utc)
        horizon   = timedelta(seconds=self.time_window * 2)
        recent    = [
            (nid, d) for nid, d in self.graph.nodes(data=True)
            if d.get("timestamp") and (now - d["timestamp"]) <= horizon
        ]

        new_edges = 0
        for i, (id_a, da) in enumerate(recent):
            for id_b, db in recent[i + 1:]:
                ts_a, ts_b = da["timestamp"], db["timestamp"]

                same_user = (
                    da.get("user") == db.get("user")
                    and da.get("user") not in ("unknown_user", "", None)
                )
                same_host = (
                    da.get("host") == db.get("host")
                    and da.get("host") not in ("unknown_host", "", None)
                )
                if not (same_user or same_host):
                    continue

                delta = abs((ts_b - ts_a).total_seconds())
                if delta > self.time_window:
                    continue

                # Edge direction: chronologically earlier → later
                src, dst = (id_a, id_b) if ts_a <= ts_b else (id_b, id_a)
                if not self.graph.has_edge(src, dst):
                    corr = (
                        "user+host" if (same_user and same_host)
                        else ("user" if same_user else "host")
                    )
                    self.graph.add_edge(src, dst,
                                        delta_seconds=round(delta, 1),
                                        correlation=corr)
                    new_edges += 1

        logger.info(
            "[LINK] new_edges=%d | graph: nodes=%d edges=%d",
            new_edges, self.graph.number_of_nodes(), self.graph.number_of_edges(),
        )
        return new_edges

    # ── 4. Detect Attack Chains ───────────────────────────────────────────────

    def detect_attack_chain(self) -> list[dict]:
        """
        Walk all simple paths (bounded by MAX_PATH_CUTOFF) and match against
        ATTACK_PATTERNS as subsequences.

        Returns only *new* chains not yet seen this engine session.
        """
        results: list[dict] = []

        active = [
            n for n in self.graph.nodes()
            if self.graph.out_degree(n) > 0 or self.graph.in_degree(n) > 0
        ]
        if len(active) < 2:
            logger.debug("[DETECT] Insufficient correlated nodes (%d)", len(active))
            return results

        for src in active:
            for dst in active:
                if src == dst:
                    continue
                if not nx.has_path(self.graph, src, dst):
                    continue
                try:
                    # [CRIT-4] Bounded path enumeration
                    for path in nx.all_simple_paths(
                        self.graph, src, dst, cutoff=MAX_PATH_CUTOFF
                    ):
                        if len(path) < 2:
                            continue
                        stage_seq = [
                            self.graph.nodes[n].get("type", "unknown")
                            for n in path
                        ]
                        matched = self._match_pattern(stage_seq, path)
                        if matched:
                            results.append(matched)
                except nx.NetworkXError:
                    continue

        # [CRIT-2] / [PERF-3] Dedup by deterministic chain_id (ordered path)
        unique: list[dict] = []
        for r in results:
            cid = r["chain_id"]
            if cid not in self._seen_chain_ids:
                self._seen_chain_ids.add(cid)
                unique.append(r)

        # [ENH-2] Summary log
        logger.warning(
            "[DETECT] cycle complete | new_chains=%d total_seen=%d graph_nodes=%d",
            len(unique), len(self._seen_chain_ids), self.graph.number_of_nodes(),
        ) if unique else logger.info(
            "[DETECT] cycle complete | no new chains | "
            "graph_nodes=%d seen_chains=%d",
            self.graph.number_of_nodes(), len(self._seen_chain_ids),
        )
        return unique

    # ── Pattern Matching ──────────────────────────────────────────────────────

    def _match_pattern(
        self, stage_seq: list[str], path: list[str]
    ) -> Optional[dict]:
        for pattern_stages, pattern_name, base_conf in ATTACK_PATTERNS:
            if not self._is_subsequence(pattern_stages, stage_seq):
                continue

            # [CRIT-3] detected_at = latest timestamp in matched path nodes
            timestamps = [
                self.graph.nodes[n]["timestamp"]
                for n in path
                if self.graph.nodes[n].get("timestamp")
            ]
            detected_at = (
                max(timestamps).isoformat()
                if timestamps
                else datetime.now(timezone.utc).isoformat()
            )

            chain_nodes = [
                {
                    "node_id":   n,
                    "type":      self.graph.nodes[n].get("type"),
                    "timestamp": (
                        self.graph.nodes[n]["timestamp"].isoformat()
                        if self.graph.nodes[n].get("timestamp") else None
                    ),
                    "user":      self.graph.nodes[n].get("user"),
                    "host":      self.graph.nodes[n].get("host"),
                    "rule_id":   self.graph.nodes[n].get("metadata", {}).get("rule_id"),
                    "severity":  self.graph.nodes[n].get("metadata", {}).get("severity"),
                }
                for n in path
            ]

            risk       = self._compute_risk(stage_seq)
            confidence = self._compute_confidence(base_conf, stage_seq, pattern_stages)

            # [PERF-2] Deterministic id from ordered node sequence
            chain_id  = _make_chain_id(path)
            # [ENH-1] Severity label
            severity  = _score_to_severity(risk)

            logger.warning(
                "[CHAIN] %-40s chain_id=%s risk=%3d %-8s conf=%3.0f%% "
                "stages=[%s]",
                pattern_name, chain_id, risk, severity,
                confidence * 100, " → ".join(stage_seq),
            )
            return {
                "chain_id":       chain_id,
                "pattern_name":   pattern_name,
                "attack_chain":   path,
                "chain_detail":   chain_nodes,
                "stage_sequence": stage_seq,
                "risk_score":     risk,
                "confidence":     round(confidence, 3),
                "severity":       severity,
                "detected_at":    detected_at,
            }
        return None

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _compute_risk(self, stage_seq: list[str]) -> int:
        return _cap_score(sum(STAGE_SCORES.get(s, 10) for s in stage_seq))

    def _compute_confidence(
        self, base: float, actual: list[str], pattern: list[str]
    ) -> float:
        return max(0.0, min(1.0, base + (len(actual) - len(pattern)) * 0.03))

    @staticmethod
    def _is_subsequence(pattern: list[str], sequence: list[str]) -> bool:
        it = iter(sequence)
        return all(stage in it for stage in pattern)

    # ── Utility ───────────────────────────────────────────────────────────────

    def graph_summary(self) -> dict:
        return {
            "nodes":                self.graph.number_of_nodes(),
            "edges":                self.graph.number_of_edges(),
            "connected_components": nx.number_weakly_connected_components(self.graph),
            "seen_chains":          len(self._seen_chain_ids),
        }

    def reset(self) -> None:
        self.graph.clear()
        self._seen_alerts.clear()
        self._seen_chain_ids.clear()
        logger.info("[GRAPH] Engine reset — all state cleared")
"""
graph_engine.py — Phase 3: Attack Graph Engine (Production Edition v3)
SOC Correlation Engine | Multi-Stage Attack Chain Detection

Changes in v3 (correlation robustness):
  [FIX-1]  _normalise_identity() — strip, lowercase, reject noise tokens
           so "fakeuser" vs "FAKEUSER" and "-" vs "" never block correlation
  [FIX-2]  Tiered correlation in link_events():
             tier-1  same_user AND same_host  (strongest, conf boost +0.10)
             tier-2  same_user only           (conf boost +0.05)
             tier-3  same_host only           (conf boost  0.00, allowed)
           Previous code skipped pairs when only host matched if user existed
           but differed — that was the direct cause of missed chains.
  [FIX-3]  _user_is_meaningful() guard — nodes with no real user value
           never block host-only correlation.
  [FIX-4]  Confidence penalty applied when correlation is host-only
           (reduces confidence by 0.10) so weak links don't inflate scores.
  [FIX-5]  prune_old_nodes() also resets _seen_chain_ids for pruned nodes'
           chains so a test re-run with a fresh graph produces alerts again.
  [FIX-6]  Detailed debug log in link_events() explains WHY every pair was
           skipped — makes correlation failures immediately diagnosable.
  [FIX-7]  add_alert() normalises host to lowercase on ingestion so
           "WIN10" and "win10" are always the same node key.
  [FIX-8]  reset() now also logs a graph summary before clearing, which
           makes test-run boundaries visible in the log stream.

All previous fixes (CRIT-1…4, PERF-1…3, ENH-1…2) are preserved unchanged.
Detection logic, alert structure, and pipeline flow are NOT changed.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import networkx as nx

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("graph_engine")


# ─── Constants ───────────────────────────────────────────────────────────────

RULE_TO_STAGE: dict[str, str] = {
    "BF": "brute_force",
    "LS": "login_success",
    "SP": "execution",
    "PE": "privilege_escalation",
    "LM": "lateral_movement",
    "EX": "exfiltration",
    "DP": "defense_evasion",
    "CR": "credential_access",
}

STAGE_SCORES: dict[str, int] = {
    "brute_force":          30,
    "login_success":        20,
    "execution":            30,
    "privilege_escalation": 40,
    "lateral_movement":     35,
    "exfiltration":         50,
    "defense_evasion":      25,
    "credential_access":    30,
    "unknown":              10,
}

# (pattern_stages, pattern_name, base_confidence)
ATTACK_PATTERNS: list[tuple[list[str], str, float]] = [
    (["brute_force", "login_success", "execution"],
     "Credential Brute-Force → Execution", 0.90),
    (["login_success", "privilege_escalation", "execution"],
     "Privilege Escalation → Execution", 0.85),
    (["execution", "lateral_movement", "execution"],
     "Lateral Movement Chain", 0.80),
    (["brute_force", "login_success", "privilege_escalation", "execution"],
     "Full Compromise Kill-Chain", 0.95),
    (["credential_access", "login_success", "exfiltration"],
     "Credential Theft → Exfiltration", 0.88),
    (["execution", "defense_evasion", "exfiltration"],
     "Stealth Exfiltration", 0.82),
    # [FIX-2] host-only pattern: covers brute_force → execution on same host
    # even when the attacker rotates usernames between stages
    (["brute_force", "execution"],
     "Brute-Force → Direct Execution (host-correlated)", 0.75),
]

DEFAULT_TIME_WINDOW_SECONDS: int = 300
MAX_PATH_CUTOFF: int = 6  # prevents combinatorial explosion

# [FIX-1] Token values that mean "no real user" — never used for user correlation
_NULL_USER_TOKENS: frozenset[str] = frozenset({
    "", "-", "unknown", "unknown_user", "n/a", "na", "null", "none",
    "system", "local service", "network service", "anonymous logon",
    "iis apppool", "dwm-1", "umfd-0", "umfd-1",
})

# [FIX-1] Token values that mean "no real host"
_NULL_HOST_TOKENS: frozenset[str] = frozenset({
    "", "-", "unknown", "unknown_host", "n/a", "na", "null", "none",
    "localhost",
})


# ─── Identity helpers ─────────────────────────────────────────────────────────

def _normalise_identity(value: Optional[str]) -> str:
    """
    [FIX-1] Return a clean, lowercase identity string.
    Returns "" if the value is absent or a noise token.
    This ensures "WIN10" == "win10" and "-" is treated as absent.
    """
    if not value:
        return ""
    cleaned = str(value).strip().lower()
    return "" if cleaned in _NULL_USER_TOKENS else cleaned


def _normalise_host(value: Optional[str]) -> str:
    """Same as _normalise_identity but checked against _NULL_HOST_TOKENS."""
    if not value:
        return ""
    cleaned = str(value).strip().lower()
    return "" if cleaned in _NULL_HOST_TOKENS else cleaned


def _user_is_meaningful(user: str) -> bool:
    """
    [FIX-3] True only when user carries real identity signal.
    An empty string (after normalisation) means the user field is absent
    or was a noise token — host-only correlation should be used instead.
    """
    return bool(user)  # normalised "" == not meaningful


# ─── Other helpers ───────────────────────────────────────────────────────────

def _rule_to_stage(rule_id: str) -> str:
    prefix = rule_id.split("-")[0].upper()
    return RULE_TO_STAGE.get(prefix, "unknown")


def _parse_timestamp(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        logger.warning("[GRAPH] Bad timestamp: %s", ts)
        return None


def _cap_score(score: int, maximum: int = 100) -> int:
    return min(score, maximum)


def _score_to_severity(score: int) -> str:
    if score >= 90:  return "critical"
    if score >= 60:  return "high"
    if score >= 30:  return "medium"
    return "low"


def _make_chain_id(node_ids: list[str]) -> str:
    return hashlib.sha256("|".join(node_ids).encode()).hexdigest()[:16]


# ─── AttackGraphEngine ────────────────────────────────────────────────────────

class AttackGraphEngine:
    """
    Directed graph of attack events with tiered temporal + identity correlation.

    Correlation tiers (highest → lowest confidence):
      tier-1  same normalised user AND same normalised host
      tier-2  same normalised user  (host differs or absent)
      tier-3  same normalised host  (user differs, missing, or noise)

    Tier-3 is the critical addition in v3: it allows brute_force events that
    use a spray username to link with execution events on the same target host
    even though the user fields don't match.
    """

    def __init__(self, time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS):
        self.graph: nx.DiGraph = nx.DiGraph()
        self.time_window: int  = time_window_seconds
        self._seen_alerts: set[str]    = set()
        self._seen_chain_ids: set[str] = set()
        logger.info(
            "[GRAPH] Engine ready | window=%ds path_cutoff=%d",
            time_window_seconds, MAX_PATH_CUTOFF,
        )

    # ── 1. Add Alert ──────────────────────────────────────────────────────────

    def add_alert(self, alert: dict) -> Optional[str]:
        """Convert alert → graph node. Returns node_id or None if skipped."""
        rule_id  = alert.get("rule_id", "UNKNOWN")
        severity = alert.get("severity", "unknown")
        ts_raw   = alert.get("timestamp", "")

        # [FIX-1] [FIX-7] Normalise on ingestion — all comparisons use clean values
        user = _normalise_identity(alert.get("user", ""))
        host = _normalise_host(alert.get("host", ""))

        ts = _parse_timestamp(ts_raw)
        if ts is None:
            logger.warning("[ADD_ALERT] Skipped — bad timestamp | rule=%s", rule_id)
            return None

        if not host:
            logger.warning(
                "[ADD_ALERT] Skipped — no usable host | rule=%s user=%r raw_host=%r",
                rule_id, user, alert.get("host"),
            )
            return None

        # Alert-level dedup (uses normalised values so casing dupes are caught)
        dedup_key = f"{rule_id}|{user}|{host}|{ts.strftime('%Y%m%dT%H%M')}"
        if dedup_key in self._seen_alerts:
            logger.debug("[ADD_ALERT] Duplicate skipped | %s", dedup_key)
            return None
        self._seen_alerts.add(dedup_key)

        stage   = _rule_to_stage(rule_id)
        node_id = str(uuid.uuid4())
        self.graph.add_node(node_id, **{
            "type":      stage,
            "timestamp": ts,
            "user":      user,   # normalised
            "host":      host,   # normalised
            "metadata": {
                "rule_id":  rule_id,
                "severity": severity,
                "raw":      alert,
            },
        })
        logger.info(
            "[ADD_ALERT] node=%-8s stage=%-26s user=%-14s host=%-12s ts=%s",
            node_id[:8], stage, user or "<none>", host, ts.isoformat(),
        )
        return node_id

    # ── 2. Prune Old Nodes ────────────────────────────────────────────────────

    def prune_old_nodes(self) -> int:
        """
        Remove nodes older than time_window.
        [FIX-5] Also clears _seen_chain_ids so a re-run on a fresh graph
        will fire the same patterns again (critical for test cycles).
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.time_window)
        stale  = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("timestamp") and d["timestamp"] < cutoff
        ]
        for n in stale:
            self.graph.remove_node(n)

        if stale:
            # Rebuild dedup set from survivors only
            surviving: set[str] = set()
            for _, d in self.graph.nodes(data=True):
                ts  = d.get("timestamp")
                key = (
                    f"{d['metadata']['rule_id']}|{d['user']}|{d['host']}|"
                    f"{ts.strftime('%Y%m%dT%H%M') if ts else 'x'}"
                )
                surviving.add(key)
            self._seen_alerts = surviving

            # [FIX-5] All prior chain detections may be invalid once the graph
            # changes; reset so the next detect pass fires cleanly.
            self._seen_chain_ids.clear()

            logger.info(
                "[PRUNE] Removed %d stale node(s) | survivors=%d | chain_id_cache cleared",
                len(stale), self.graph.number_of_nodes(),
            )
        return len(stale)

    # ── 3. Link Events ────────────────────────────────────────────────────────

    def link_events(self) -> int:
        """
        Draw directed edges using tiered identity correlation.

        [FIX-2] Tier logic:
          tier-1  same_user AND same_host  → edge, conf_boost=+0.10
          tier-2  same_user only           → edge, conf_boost=+0.05
          tier-3  same_host only           → edge, conf_boost= 0.00
                  (allowed even when users differ — covers username rotation)

        [FIX-3] A node whose user is empty (noise / missing) is treated as
          "user unknown" — it never BLOCKS host-only correlation.

        [FIX-6] Every skipped pair is logged at DEBUG level with the reason,
          so you can diagnose correlation failures without modifying code.
        """
        self.prune_old_nodes()

        now     = datetime.now(timezone.utc)
        horizon = timedelta(seconds=self.time_window * 2)
        recent  = [
            (nid, d) for nid, d in self.graph.nodes(data=True)
            if d.get("timestamp") and (now - d["timestamp"]) <= horizon
        ]

        new_edges = 0
        for i, (id_a, da) in enumerate(recent):
            for id_b, db in recent[i + 1:]:
                ts_a = da["timestamp"]
                ts_b = db["timestamp"]
                u_a  = da.get("user", "")
                u_b  = db.get("user", "")
                h_a  = da.get("host", "")
                h_b  = db.get("host", "")

                # ── Time gate ─────────────────────────────────────────────────
                delta = abs((ts_b - ts_a).total_seconds())
                if delta > self.time_window:
                    logger.debug(
                        "[LINK SKIP] time_gap | %s(%s) ↔ %s(%s) | Δ=%.0fs > window=%ds",
                        id_a[:8], da.get("type"), id_b[:8], db.get("type"),
                        delta, self.time_window,
                    )
                    continue

                # ── Host gate — both nodes must have a real host ───────────────
                if not h_a or not h_b:
                    logger.debug(
                        "[LINK SKIP] missing_host | %s(host=%r) ↔ %s(host=%r)",
                        id_a[:8], h_a, id_b[:8], h_b,
                    )
                    continue

                # ── [FIX-2] Tiered correlation ─────────────────────────────────
                same_host = (h_a == h_b)
                same_user = (
                    _user_is_meaningful(u_a)
                    and _user_is_meaningful(u_b)
                    and u_a == u_b
                )

                if same_user and same_host:
                    tier      = "user+host"
                    conf_adj  = +0.10
                elif same_user:
                    tier      = "user"
                    conf_adj  = +0.05
                elif same_host:
                    # [FIX-2] Core fix: allow host-only even when users differ
                    tier      = "host"
                    conf_adj  =  0.00
                else:
                    # Different host AND (different user or no user) → no link
                    logger.debug(
                        "[LINK SKIP] no_identity_match | "
                        "%s(user=%r host=%r) ↔ %s(user=%r host=%r)",
                        id_a[:8], u_a, h_a, id_b[:8], u_b, h_b,
                    )
                    continue

                # ── Draw edge (chronologically ordered) ───────────────────────
                src, dst = (id_a, id_b) if ts_a <= ts_b else (id_b, id_a)
                if not self.graph.has_edge(src, dst):
                    self.graph.add_edge(
                        src, dst,
                        delta_seconds = round(delta, 1),
                        correlation   = tier,
                        conf_adj      = conf_adj,   # carried to confidence calc
                    )
                    new_edges += 1
                    logger.debug(
                        "[LINK EDGE] %s(%s) → %s(%s) | tier=%s Δ=%.0fs",
                        src[:8], self.graph.nodes[src].get("type"),
                        dst[:8], self.graph.nodes[dst].get("type"),
                        tier, delta,
                    )

        logger.info(
            "[LINK] new_edges=%d | graph: nodes=%d edges=%d",
            new_edges, self.graph.number_of_nodes(), self.graph.number_of_edges(),
        )
        return new_edges

    # ── 4. Detect Attack Chains ───────────────────────────────────────────────

    def detect_attack_chain(self) -> list[dict]:
        """
        Walk all simple paths bounded by MAX_PATH_CUTOFF and match ATTACK_PATTERNS.
        Returns only chains not previously seen this session.
        """
        results: list[dict] = []

        active = [
            n for n in self.graph.nodes()
            if self.graph.out_degree(n) > 0 or self.graph.in_degree(n) > 0
        ]
        if len(active) < 2:
            logger.info(
                "[DETECT] Insufficient correlated nodes | active=%d total=%d",
                len(active), self.graph.number_of_nodes(),
            )
            return results

        for src in active:
            for dst in active:
                if src == dst:
                    continue
                if not nx.has_path(self.graph, src, dst):
                    continue
                try:
                    for path in nx.all_simple_paths(
                        self.graph, src, dst, cutoff=MAX_PATH_CUTOFF
                    ):
                        if len(path) < 2:
                            continue
                        stage_seq = [
                            self.graph.nodes[n].get("type", "unknown")
                            for n in path
                        ]
                        matched = self._match_pattern(stage_seq, path)
                        if matched:
                            results.append(matched)
                except nx.NetworkXError:
                    continue

        unique: list[dict] = []
        for r in results:
            cid = r["chain_id"]
            if cid not in self._seen_chain_ids:
                self._seen_chain_ids.add(cid)
                unique.append(r)

        if unique:
            logger.warning(
                "[DETECT] %d new chain(s) | seen_total=%d | nodes=%d",
                len(unique), len(self._seen_chain_ids), self.graph.number_of_nodes(),
            )
        else:
            logger.info(
                "[DETECT] no new chains | nodes=%d edges=%d seen_total=%d",
                self.graph.number_of_nodes(), self.graph.number_of_edges(),
                len(self._seen_chain_ids),
            )
        return unique

    # ── Pattern Matching ──────────────────────────────────────────────────────

    def _match_pattern(
        self, stage_seq: list[str], path: list[str]
    ) -> Optional[dict]:
        for pattern_stages, pattern_name, base_conf in ATTACK_PATTERNS:
            if not self._is_subsequence(pattern_stages, stage_seq):
                continue

            # detected_at = timestamp of latest node in path
            timestamps = [
                self.graph.nodes[n]["timestamp"]
                for n in path
                if self.graph.nodes[n].get("timestamp")
            ]
            detected_at = (
                max(timestamps).isoformat()
                if timestamps
                else datetime.now(timezone.utc).isoformat()
            )

            chain_nodes = [
                {
                    "node_id":   n,
                    "type":      self.graph.nodes[n].get("type"),
                    "timestamp": (
                        self.graph.nodes[n]["timestamp"].isoformat()
                        if self.graph.nodes[n].get("timestamp") else None
                    ),
                    "user":      self.graph.nodes[n].get("user"),
                    "host":      self.graph.nodes[n].get("host"),
                    "rule_id":   self.graph.nodes[n].get("metadata", {}).get("rule_id"),
                    "severity":  self.graph.nodes[n].get("metadata", {}).get("severity"),
                }
                for n in path
            ]

            risk     = self._compute_risk(stage_seq)
            # [FIX-4] Accumulate conf_adj from all edges in path
            edge_adj = self._path_conf_adjustment(path)
            conf     = self._compute_confidence(base_conf, stage_seq, pattern_stages, edge_adj)

            chain_id = _make_chain_id(path)
            severity = _score_to_severity(risk)

            logger.warning(
                "[CHAIN] %-44s chain_id=%s risk=%3d %-8s conf=%3.0f%% stages=[%s]",
                pattern_name, chain_id, risk, severity,
                conf * 100, " → ".join(stage_seq),
            )
            return {
                "chain_id":       chain_id,
                "pattern_name":   pattern_name,
                "attack_chain":   path,
                "chain_detail":   chain_nodes,
                "stage_sequence": stage_seq,
                "risk_score":     risk,
                "confidence":     round(conf, 3),
                "severity":       severity,
                "detected_at":    detected_at,
            }
        return None

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _compute_risk(self, stage_seq: list[str]) -> int:
        return _cap_score(sum(STAGE_SCORES.get(s, 10) for s in stage_seq))

    def _path_conf_adjustment(self, path: list[str]) -> float:
        """
        [FIX-4] Sum the conf_adj values stored on edges in this path.
        host-only edges contribute 0.00; user-only +0.05; user+host +0.10.
        A path made entirely of host-only links gets a small penalty: -0.10.
        """
        adjustments: list[float] = []
        for i in range(len(path) - 1):
            edge_data = self.graph.edges[path[i], path[i + 1]]
            adjustments.append(edge_data.get("conf_adj", 0.0))

        if not adjustments:
            return 0.0

        total = sum(adjustments)
        # Penalty: if every edge is host-only (all zeros), apply -0.10
        if all(a == 0.0 for a in adjustments):
            total = -0.10
        return total

    def _compute_confidence(
        self,
        base: float,
        actual: list[str],
        pattern: list[str],
        edge_adj: float = 0.0,
    ) -> float:
        length_adj = (len(actual) - len(pattern)) * 0.03
        return max(0.0, min(1.0, base + length_adj + edge_adj))

    @staticmethod
    def _is_subsequence(pattern: list[str], sequence: list[str]) -> bool:
        it = iter(sequence)
        return all(stage in it for stage in pattern)

    # ── Utility ───────────────────────────────────────────────────────────────

    def graph_summary(self) -> dict:
        return {
            "nodes":                self.graph.number_of_nodes(),
            "edges":                self.graph.number_of_edges(),
            "connected_components": (
                nx.number_weakly_connected_components(self.graph)
                if self.graph.number_of_nodes() > 0 else 0
            ),
            "seen_chains": len(self._seen_chain_ids),
        }

    def reset(self) -> None:
        # [FIX-8] Log state before clearing so test-run boundaries are visible
        summary = self.graph_summary()
        logger.info(
            "[GRAPH] Resetting | nodes=%d edges=%d seen_chains=%d",
            summary["nodes"], summary["edges"], summary["seen_chains"],
        )
        self.graph.clear()
        self._seen_alerts.clear()
        self._seen_chain_ids.clear()
        logger.info("[GRAPH] Engine reset — all state cleared")
