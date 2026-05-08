"""
soar_engine.py — Mock SOAR Playbook Engine
Phase 7: Simulated Security Orchestration, Automation, and Response

NO real system calls. NO firewall changes. NO endpoint isolation commands.
All actions are simulated for XDR-style response automation.
"""

from datetime import datetime, timezone
import logging

logger = logging.getLogger("soc.soar")

# ── Playbook Definitions ───────────────────────────────────────────────────────

_PLAYBOOKS: dict[str, dict] = {
    "BF-IP-001": {
        "playbook": "Brute Force Response",
        "actions": ["block_ip", "create_ticket", "notify_soc"],
    },
    "BF-USR-001": {
        "playbook": "Brute Force Response",
        "actions": ["block_ip", "create_ticket", "notify_soc"],
    },
    "SP-001": {
        "playbook": "Malware Execution Response",
        "actions": ["isolate_host", "kill_process", "notify_ir_team"],
    },
    "PE-001": {
        "playbook": "Privilege Escalation Response",
        "actions": ["disable_account", "escalate_priority", "notify_soc"],
    },
}


# ── Engine ─────────────────────────────────────────────────────────────────────

async def execute_playbook(alert: dict) -> dict:
    """
    Inspect alert rule_id and return simulated SOAR response actions.

    Returns empty dict if no playbook matches.
    NO real system calls are made — all actions are mock/simulated.
    """
    rule_id = (alert.get("rule_id") or "").strip()

    playbook_def = _PLAYBOOKS.get(rule_id)
    if not playbook_def:
        return {}

    executed_at = datetime.now(timezone.utc).isoformat()

    actions = [
        {"action": action, "status": "success"}
        for action in playbook_def["actions"]
    ]

    result = {
        "playbook":    playbook_def["playbook"],
        "status":      "executed",
        "actions":     actions,
        "executed_at": executed_at,
    }

    logger.info(
        "[SOAR] rule=%-15s playbook='%s' actions=%s",
        rule_id,
        result["playbook"],
        [a["action"] for a in actions],
    )

    return result
