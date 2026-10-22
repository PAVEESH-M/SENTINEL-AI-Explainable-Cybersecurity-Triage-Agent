"""SENTINEL AI tools: cybersecurity triage investigation.

Four tools cover the full investigation pipeline:
    lookup_indicators   -- search the synthetic threat-intel dataset (read-only)
    get_policy          -- retrieve security policy rules for a threat type (read-only)
    summarize_evidence  -- build a structured evidence summary for the current alert (read-only)
    propose_action      -- submit a proposed security action for the guardrail check (GUARDED)

All data is synthetic and in-memory. No real URLs are visited, no emails are sent, no
external services are called. Quarantine and block operations are simulated.

One-line docstrings on each @tool are required: the model reads them, and the tool-selection
pattern uses them as option descriptions.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from strands import tool

from decider_kit.data import load

# ---------------------------------------------------------------------------
# Synthetic threat-intelligence dataset (loaded from agent/data/)
# ---------------------------------------------------------------------------

def _load_indicators() -> list[dict[str, Any]]:
    try:
        return list(load("threat_indicators"))
    except FileNotFoundError:
        return []

def _load_policies() -> list[dict[str, Any]]:
    try:
        return list(load("security_policies"))
    except FileNotFoundError:
        return []

_INDICATORS: list[dict[str, Any]] = _load_indicators()
_POLICIES: list[dict[str, Any]] = _load_policies()

# Audit log: every proposed, approved, blocked, and executed action.
AUDIT_LOG: list[dict[str, Any]] = []

def reset_state() -> None:
    """Restore audit log to empty state (used by tests)."""
    AUDIT_LOG.clear()


def _extract_domains_and_urls(text: str) -> list[str]:
    """Extract domain names and URLs from arbitrary text (no network calls)."""
    url_pattern = r'https?://[^\s<>"\')\]]+[^\s<>"\')\].,;]'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|co|io|xyz|ru|biz|online|site|live)\b'
    found: list[str] = []
    for m in re.findall(url_pattern, text):
        found.append(m)
    for m in re.findall(domain_pattern, text):
        # avoid duplicating domains already inside a found URL
        if not any(m in u for u in found):
            found.append(m)
    return list(dict.fromkeys(found))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Read-only investigation tools
# ---------------------------------------------------------------------------

@tool
def lookup_indicators(query: str) -> dict[str, Any]:
    """Search the threat-intelligence database for domains, URLs, or keywords in a message (read-only)."""
    query_lower = query.lower()
    # Extract observable indicators from the query text
    extracted = _extract_domains_and_urls(query)
    matches: list[dict[str, Any]] = []

    # Direct value matches (URL or domain)
    for ind in _INDICATORS:
        val = ind.get("value", "").lower()
        if val and val in query_lower:
            matches.append({
                "id": ind["id"],
                "type": ind["type"],
                "value": ind["value"],
                "threat_type": ind["threat_type"],
                "confidence": ind["confidence"],
                "tags": ind.get("tags", []),
                "description": ind["description"],
            })
        # Also match any extracted URL/domain against indicator values
        for obs in extracted:
            if val and (obs.lower() == val or obs.lower().endswith("." + val) or val in obs.lower()):
                entry = {
                    "id": ind["id"],
                    "type": ind["type"],
                    "value": ind["value"],
                    "threat_type": ind["threat_type"],
                    "confidence": ind["confidence"],
                    "tags": ind.get("tags", []),
                    "description": ind["description"],
                }
                if entry not in matches:
                    matches.append(entry)

    # Keyword/tag search if no direct hit
    if not matches:
        keywords = [w.strip() for w in query_lower.replace(",", " ").split() if len(w) > 3]
        for ind in _INDICATORS:
            text_blob = (
                ind.get("value", "") + " " +
                ind.get("description", "") + " " +
                " ".join(ind.get("tags", []))
            ).lower()
            if any(kw in text_blob for kw in keywords):
                matches.append({
                    "id": ind["id"],
                    "type": ind["type"],
                    "value": ind["value"],
                    "threat_type": ind["threat_type"],
                    "confidence": ind["confidence"],
                    "tags": ind.get("tags", []),
                    "description": ind["description"],
                })

    threat_types = list({m["threat_type"] for m in matches})
    return {
        "query": query[:200],
        "extracted_observables": extracted,
        "match_count": len(matches),
        "matches": matches[:8],  # cap at 8 results
        "threat_types_found": threat_types,
    }


@tool
def get_policy(threat_type: str) -> dict[str, Any]:
    """Retrieve the security policy rules that apply to a given threat type (read-only)."""
    threat_lower = threat_type.lower().replace("-", " ").replace("_", " ")
    applicable: list[dict[str, Any]] = []
    for pol in _POLICIES:
        applies_to = [t.lower() for t in pol.get("applies_to", [])]
        tags_match = any(
            t in threat_lower or threat_lower in t
            for t in applies_to
        )
        if tags_match:
            applicable.append({
                "policy_id": pol["policy_id"],
                "name": pol["name"],
                "automatic_action": pol["automatic_action"],
                "requires_human_review": pol["requires_human_review"],
                "escalate_if": pol.get("escalate_if", []),
                "description": pol["description"],
            })
    if not applicable:
        applicable = [{
            "policy_id": "POL-DEFAULT",
            "name": "Default Caution Policy",
            "automatic_action": "hold_for_review",
            "requires_human_review": True,
            "escalate_if": [],
            "description": "No specific policy found. Default: hold for human review.",
        }]
    return {
        "threat_type": threat_type,
        "policies_found": len(applicable),
        "policies": applicable,
    }


@tool
def summarize_evidence(alert_text: str, indicator_results: str) -> dict[str, Any]:
    """Build a structured evidence summary combining the alert text and indicator lookup results (read-only)."""
    # Parse indicator_results if it is a JSON string from a previous lookup_indicators call
    indicators: list[dict[str, Any]] = []
    try:
        parsed = json.loads(indicator_results)
        indicators = parsed.get("matches", []) if isinstance(parsed, dict) else []
    except (json.JSONDecodeError, TypeError):
        indicators = []

    high_conf = [i for i in indicators if i.get("confidence") == "high"]
    med_conf = [i for i in indicators if i.get("confidence") == "medium"]
    benign = [i for i in indicators if i.get("threat_type") == "benign"]
    threat = [i for i in indicators if i.get("threat_type") not in ("benign", "")]

    # Derive overall threat assessment
    if not indicators:
        assessment = "no_indicators_found"
        severity = "unknown"
    elif benign and not threat:
        assessment = "likely_benign"
        severity = "low"
    elif high_conf:
        assessment = "confirmed_threat"
        severity = "high"
    elif med_conf:
        assessment = "suspected_threat"
        severity = "medium"
    else:
        assessment = "insufficient_evidence"
        severity = "low"

    threat_types = list({i["threat_type"] for i in threat})
    tags = list({t for i in threat for t in i.get("tags", [])})

    # Urgency signals in the alert text (simple heuristics — the LLM does the deeper reasoning)
    urgency_words = ["urgent", "immediate", "wire", "transfer", "verify", "confirm",
                     "suspended", "expires", "24 hour", "click here", "act now", "overdue"]
    alert_lower = alert_text.lower()
    urgency_signals = [w for w in urgency_words if w in alert_lower]

    return {
        "assessment": assessment,
        "severity": severity,
        "threat_types": threat_types,
        "tags": tags,
        "verified_indicator_count": len(indicators),
        "high_confidence_hits": len(high_conf),
        "medium_confidence_hits": len(med_conf),
        "benign_indicators": len(benign),
        "urgency_signals_in_alert": urgency_signals,
        "indicators": [{"value": i["value"], "threat_type": i["threat_type"], "confidence": i["confidence"]} for i in indicators[:5]],
        "note": "This summary is based solely on the synthetic threat-intel dataset. Treat as one input among many.",
    }


# ---------------------------------------------------------------------------
# Guarded tool — must match GUARDED_TOOLS in decision.py
# ---------------------------------------------------------------------------

@tool
def propose_action(
    action_type: str,
    threat_type: str,
    confidence: str,
    alert_id: str,
    reasoning: str,
) -> dict[str, Any]:
    """Propose a security action (quarantine, block, escalate, allow) for the guardrail check before execution.

    This tool is the ONLY entry point for consequential actions. Strands Decider 2B checks
    whether the action is authorized, evidence-grounded, and policy-compliant before it
    executes. All actions are simulated — no real email systems are affected.

    action_type: one of quarantine | block_sender | escalate | allow | hold_for_review
    threat_type: the identified threat category (e.g. phishing, malware, bec, benign)
    confidence:  high | medium | low
    alert_id:    a short identifier for the alert being acted on
    reasoning:   a one-sentence explanation of why this action is proposed
    """
    valid_actions = {"quarantine", "block_sender", "escalate", "allow", "hold_for_review"}
    if action_type not in valid_actions:
        return {"error": f"unknown action_type '{action_type}'. Use one of: {sorted(valid_actions)}"}

    entry = {
        "action": action_type,
        "threat_type": threat_type,
        "confidence": confidence,
        "alert_id": alert_id,
        "reasoning": reasoning,
        "outcome": "executed",  # GuardrailGuard may have blocked this before we got here
    }
    AUDIT_LOG.append(entry)
    return {
        "executed": action_type,
        "alert_id": alert_id,
        "threat_type": threat_type,
        "confidence": confidence,
        "simulated": True,
        "message": (
            f"[SIMULATED] Action '{action_type}' recorded for alert '{alert_id}'. "
            "No real email system was affected."
        ),
    }


TOOLS = [lookup_indicators, get_policy, summarize_evidence, propose_action]
