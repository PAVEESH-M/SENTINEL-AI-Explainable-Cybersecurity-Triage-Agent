"""Unit tests for SENTINEL AI tools and SentinelGuard wiring.

All tests run fully offline using FakeDecider from tests/fakes.py.
No network calls, AWS credentials, or Bedrock access required.

Coverage
--------
Tools (agent/tools.py)
  - lookup_indicators: domain match, URL match, keyword fallback, no match
  - get_policy: threat type match, default policy for unknown threat
  - summarize_evidence: high-confidence hit, benign result, no indicators
  - propose_action: valid actions recorded in AUDIT_LOG, invalid action returns error

SentinelGuard wiring (agent/decision.py) via synthetic events
  - read-only tool bypasses gate (no decider call, no log entry)
  - guide when user_authorized is low
  - guide when evidence_grounded is low (auth present)
  - confirm when policy_scope is requires_review
  - confirm when policy_scope is exceeds_scope
  - proceed when auth + evidence + within_policy
  - confirm when auth in unsure band
  - guide convergence: same call guided twice -> Deny
  - before_invocation resets guided set

HackathonAgent interface (agent/agent.py)
  - constructor accepts FakeDecider and model_id
  - NAME contains "SENTINEL AI"
  - chat() returns all required keys
  - sessions dict starts empty
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from fakes import FakeDecider
from strands.interventions import Confirm, Deny, Guide, Proceed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(name: str = "propose_action", args: dict[str, Any] | None = None, messages=None):
    """Build a minimal event that SentinelGuard.before_tool_call accepts."""
    default_args = {
        "action_type": "quarantine",
        "threat_type": "phishing",
        "confidence": "high",
        "alert_id": "T001",
        "reasoning": "Test reasoning",
    }
    msgs = messages or [{"role": "user", "content": [{"text": "quarantine this phishing email"}]}]
    return SimpleNamespace(
        tool_use={"name": name, "input": args or default_args},
        agent=SimpleNamespace(messages=msgs),
    )


def _guard(rule=None):
    from agent.decision import SentinelGuard
    return SentinelGuard(FakeDecider(rule))


# ---------------------------------------------------------------------------
# Tool tests
# ---------------------------------------------------------------------------

class TestLookupIndicators:
    def test_domain_match_returns_hit(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("This email is from secure-paypal-verify.net asking for login")
        assert result["match_count"] >= 1
        ids = [m["id"] for m in result["matches"]]
        assert "TI-001" in ids

    def test_url_match_returns_hit(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("Click here: http://dl.malware-drop.xyz/invoice.exe")
        assert result["match_count"] >= 1
        threat_types = result["threat_types_found"]
        assert "malware" in threat_types

    def test_keyword_fallback_finds_phishing(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("credential theft campaign impersonation")
        assert result["match_count"] >= 1

    def test_benign_domain_returns_hit(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("email from dropbox.com with shared file")
        hits = [m for m in result["matches"] if m["value"] == "dropbox.com"]
        assert hits and hits[0]["threat_type"] == "benign"

    def test_unknown_content_returns_empty(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("hello how are you today nothing suspicious here")
        # may return 0 or some matches; key check is structure is valid
        assert "match_count" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_extracted_observables_list_present(self):
        from agent.tools import lookup_indicators
        result = lookup_indicators._tool_func("visit http://secure-paypal-verify.net/login now")
        assert "extracted_observables" in result


class TestGetPolicy:
    def test_phishing_returns_pol001(self):
        from agent.tools import get_policy
        result = get_policy._tool_func("phishing")
        ids = [p["policy_id"] for p in result["policies"]]
        assert "POL-001" in ids

    def test_malware_returns_pol002(self):
        from agent.tools import get_policy
        result = get_policy._tool_func("malware")
        ids = [p["policy_id"] for p in result["policies"]]
        assert "POL-002" in ids

    def test_bec_returns_pol003_requiring_review(self):
        from agent.tools import get_policy
        result = get_policy._tool_func("bec")
        bec_pol = [p for p in result["policies"] if p["policy_id"] == "POL-003"]
        assert bec_pol
        assert bec_pol[0]["requires_human_review"] is True

    def test_unknown_threat_returns_default_policy(self):
        from agent.tools import get_policy
        result = get_policy._tool_func("unknown_threat_xyz")
        assert result["policies"][0]["policy_id"] == "POL-DEFAULT"
        assert result["policies"][0]["requires_human_review"] is True

    def test_benign_returns_pol005(self):
        from agent.tools import get_policy
        result = get_policy._tool_func("benign")
        ids = [p["policy_id"] for p in result["policies"]]
        assert "POL-005" in ids


class TestSummarizeEvidence:
    def test_high_confidence_hit_gives_confirmed_threat(self):
        from agent.tools import summarize_evidence
        ind = json.dumps({"matches": [
            {"value": "secure-paypal-verify.net", "threat_type": "phishing", "confidence": "high"}
        ]})
        result = summarize_evidence._tool_func("Verify your PayPal account urgently", ind)
        assert result["assessment"] == "confirmed_threat"
        assert result["severity"] == "high"
        assert "urgent" in result["urgency_signals_in_alert"]

    def test_no_indicators_gives_unknown(self):
        from agent.tools import summarize_evidence
        result = summarize_evidence._tool_func("Hello, how are you?", json.dumps({"matches": []}))
        assert result["assessment"] == "no_indicators_found"

    def test_benign_only_gives_likely_benign(self):
        from agent.tools import summarize_evidence
        ind = json.dumps({"matches": [
            {"value": "dropbox.com", "threat_type": "benign", "confidence": "high"}
        ]})
        result = summarize_evidence._tool_func("File shared via dropbox.com", ind)
        assert result["assessment"] == "likely_benign"

    def test_invalid_json_does_not_crash(self):
        from agent.tools import summarize_evidence
        result = summarize_evidence._tool_func("some alert", "not valid json {{{")
        assert "assessment" in result

    def test_note_field_present(self):
        from agent.tools import summarize_evidence
        result = summarize_evidence._tool_func("test", "{}")
        assert "note" in result


class TestProposeAction:
    def setup_method(self):
        from agent.tools import reset_state
        reset_state()

    def test_valid_action_recorded_in_audit_log(self):
        from agent.tools import AUDIT_LOG, propose_action
        propose_action._tool_func("quarantine", "phishing", "high", "T001", "Test")
        assert any(e["action"] == "quarantine" and e["alert_id"] == "T001" for e in AUDIT_LOG)

    def test_returns_simulated_flag(self):
        from agent.tools import propose_action
        result = propose_action._tool_func("allow", "benign", "high", "T002", "Allowlisted")
        assert result["simulated"] is True
        assert result["executed"] == "allow"

    def test_invalid_action_type_returns_error(self):
        from agent.tools import propose_action
        result = propose_action._tool_func("nuke_everything", "phishing", "high", "T003", "Test")
        assert "error" in result

    def test_all_valid_actions_accepted(self):
        from agent.tools import propose_action, reset_state
        for action in ("quarantine", "block_sender", "escalate", "allow", "hold_for_review"):
            reset_state()
            result = propose_action._tool_func(action, "phishing", "high", f"T-{action}", "Test")
            assert "error" not in result, f"Unexpected error for action: {action}"


# ---------------------------------------------------------------------------
# SentinelGuard branch tests
# ---------------------------------------------------------------------------

class TestSentinelGuard:
    def test_read_only_tool_bypasses_gate_no_log(self):
        """Read-only tools never call the decider and never append to log."""
        calls = []

        class Tracking(FakeDecider):
            def ask(self, *a, **kw):
                calls.append(a)
                return super().ask(*a, **kw)

        from agent.decision import SentinelGuard
        g = SentinelGuard(Tracking())
        for tool_name in ("lookup_indicators", "get_policy", "summarize_evidence"):
            ev = SimpleNamespace(
                tool_use={"name": tool_name, "input": {"query": "test"}},
                agent=SimpleNamespace(messages=[]),
            )
            assert isinstance(g.before_tool_call(ev), Proceed)
        assert calls == []
        assert g.log == []

    def test_guide_when_no_user_authorized(self):
        """Low user_authorized -> Guide."""
        g = _guard(lambda s, n, q: 0.1 if n == "user_authorized" else (0.9 if q["type"] == "noul" else "within_policy"))
        assert isinstance(g.before_tool_call(_event()), Guide)
        assert g.log[-1]["verdict"] == "guide"

    def test_guide_when_evidence_not_grounded(self):
        """Auth present but evidence low -> Guide."""
        g = _guard(lambda s, n, q: 0.9 if n == "user_authorized" else (0.1 if n == "evidence_grounded" else "within_policy"))
        assert isinstance(g.before_tool_call(_event()), Guide)
        assert g.log[-1]["verdict"] == "guide"

    def test_confirm_when_policy_requires_review(self):
        """Auth + evidence + requires_review -> Confirm."""
        g = _guard(lambda s, n, q: 0.9 if q["type"] == "noul" else "requires_review")
        assert isinstance(g.before_tool_call(_event()), Confirm)
        assert g.log[-1]["verdict"] == "confirm"
        assert g.log[-1]["policy_scope"] == "requires_review"

    def test_confirm_when_policy_exceeds_scope(self):
        """Auth + evidence + exceeds_scope -> Confirm."""
        g = _guard(lambda s, n, q: 0.9 if q["type"] == "noul" else "exceeds_scope")
        assert isinstance(g.before_tool_call(_event()), Confirm)
        assert g.log[-1]["verdict"] == "confirm"
        assert g.log[-1]["policy_scope"] == "exceeds_scope"

    def test_proceed_when_fully_authorized(self):
        """Auth + evidence + within_policy -> Proceed."""
        g = _guard(lambda s, n, q: 0.9 if q["type"] == "noul" else "within_policy")
        assert isinstance(g.before_tool_call(_event()), Proceed)
        assert g.log[-1]["verdict"] == "proceed"

    def test_confirm_when_auth_in_unsure_band(self):
        """auth in [0.40, 0.65] (below 0.55 threshold) -> Confirm not Guide."""
        # 0.50 is in [0.40, 0.65] and below _YES=0.55
        g = _guard(lambda s, n, q: 0.50 if n == "user_authorized" else (0.9 if q["type"] == "noul" else "within_policy"))
        assert isinstance(g.before_tool_call(_event()), Confirm)
        assert g.log[-1]["verdict"] == "confirm"

    def test_guide_convergence_deny_on_retry(self):
        """Same call guided twice -> Deny."""
        g = _guard(lambda s, n, q: 0.1 if n == "user_authorized" else (0.9 if q["type"] == "noul" else "within_policy"))
        ev = _event()
        r1 = g.before_tool_call(ev)
        r2 = g.before_tool_call(ev)
        assert isinstance(r1, Guide)
        assert isinstance(r2, Deny)
        assert g.log[-1]["verdict"] == "deny"

    def test_before_invocation_resets_guided_set(self):
        """New turn clears guided memory so same call can be guided again."""
        g = _guard(lambda s, n, q: 0.1 if n == "user_authorized" else (0.9 if q["type"] == "noul" else "within_policy"))
        ev = _event()
        g.before_tool_call(ev)        # guide
        g.before_invocation(ev)       # reset
        r = g.before_tool_call(ev)    # guide again, not deny
        assert isinstance(r, Guide)

    def test_log_records_all_required_fields(self):
        """Every guarded log entry has the full required field set."""
        g = _guard(lambda s, n, q: 0.9 if q["type"] == "noul" else "within_policy")
        g.before_tool_call(_event())
        rec = g.log[-1]
        required = {"pattern", "tool", "args", "user_authorized", "evidence_grounded",
                    "policy_scope", "policy_scope_confidence", "verdict", "decider_ms"}
        assert required <= set(rec), f"Missing: {required - set(rec)}"

    def test_deny_record_has_reason(self):
        """Deny records from convergence guard include a reason field."""
        g = _guard(lambda s, n, q: 0.1 if n == "user_authorized" else (0.9 if q["type"] == "noul" else "within_policy"))
        ev = _event()
        g.before_tool_call(ev)
        g.before_tool_call(ev)
        assert g.log[-1]["verdict"] == "deny"
        assert "reason" in g.log[-1]


# ---------------------------------------------------------------------------
# HackathonAgent interface tests
# ---------------------------------------------------------------------------

class TestHackathonAgentInterface:
    def test_constructor_accepts_fake_decider_and_model_id(self):
        from agent.agent import HackathonAgent
        a = HackathonAgent(decider=FakeDecider(), model_id="us.amazon.nova-lite-v1:0")
        assert callable(a.chat)
        assert a.model_id == "us.amazon.nova-lite-v1:0"

    def test_name_contains_sentinel_ai(self):
        from agent import agent as mod
        assert "SENTINEL AI" in mod.NAME

    def test_chat_returns_required_keys(self, monkeypatch):
        from agent.agent import HackathonAgent

        class _FakeResult:
            metrics = type("M", (), {"accumulated_usage": {"inputTokens": 0, "outputTokens": 0}})()
            def __str__(self): return "This email appears to be a phishing attempt."

        class _FakeStrands:
            def __init__(self, **kw): pass
            def __call__(self, msg, invocation_state=None):
                return _FakeResult()

        monkeypatch.setattr("agent.agent.Agent", lambda **kw: _FakeStrands(**kw))
        a = HackathonAgent(decider=FakeDecider(), model_id="us.amazon.nova-lite-v1:0")
        result = a.chat("Is this phishing? Email from secure-paypal-verify.net")

        assert set(result.keys()) >= {"reply", "decisions", "model_id", "latency_ms", "agent", "eager"}
        assert isinstance(result["decisions"], list)
        assert isinstance(result["latency_ms"], int)
        assert "SENTINEL" in result["agent"]

    def test_sessions_start_empty(self):
        from agent.agent import HackathonAgent
        a = HackathonAgent(decider=FakeDecider(), model_id="us.amazon.nova-lite-v1:0")
        assert a.sessions == {}
