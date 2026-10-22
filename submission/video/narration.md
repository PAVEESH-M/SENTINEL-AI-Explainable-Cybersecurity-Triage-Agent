# SENTINEL AI — Demo Video Narration

**Target duration:** under 3 minutes  
**Recorded video:** submission/video/demo.mp4  
**Kit check reports:** 91 seconds (PASS — under 3-minute limit)

---

> **NOTE:** The existing demo.mp4 (91 seconds) was recorded from the kit's original store-support
> example agent. SENTINEL AI is the replacement agent in `agent/`. The narration below describes
> the SENTINEL AI demo script that should be recorded when Bedrock credentials are restored.
> The video file is preserved; the narration is updated to match the current project.

---

## Scene plan (for re-recording with SENTINEL AI)

### [0:00–0:15] Title card
- Screen: "SENTINEL AI — Explainable Cybersecurity Triage Agent"
- Sub: "Built with the AWS User Group Madurai Strands Decider hackathon kit"
- Narration: "Security teams triage hundreds of suspicious emails every day.
  Most AI tools give you a verdict — but not an explanation, and not a guarantee
  they won't act on unverified evidence."

### [0:15–0:30] Problem statement
- Screen: dashboard at http://127.0.0.1:8501 — empty state
- Narration: "SENTINEL AI is a cybersecurity triage agent that investigates suspicious
  messages step by step and gates every consequential response with Strands Decider 2B —
  a dedicated decision model that checks authorization, evidence, and policy scope
  before any action executes."

### [0:30–1:00] Turn 1 — Analysis without authorization
- User types: "Can you check this email? It says: Your PayPal account has been limited.
  Verify at http://secure-paypal-verify.net/login"
- Agent: looks up secure-paypal-verify.net in the threat-intel database,
  finds TI-001 (high-confidence phishing), retrieves POL-001, summarizes evidence,
  reports finding but does NOT quarantine (user only asked to check).
- Right panel: decision card showing user_authorized ~0.1, evidence_grounded ~0.9,
  verdict: guide
- Narration: "The agent found a confirmed phishing domain, but the user only asked to
  check. Strands Decider 2B saw no explicit authorization, so no action was taken."

### [1:00–1:30] Turn 2 — Authorized quarantine
- User types: "That's phishing. Quarantine it please."
- Agent: proposes quarantine action. Decider checks: user_authorized YES,
  evidence_grounded YES, policy_scope within_policy → PROCEED.
- Right panel: decision card with high probabilities on all three questions, verdict: proceed
- Narration: "Now with explicit authorization and verified evidence, the decider approves
  the quarantine. The action is logged and simulated — no real mail system is affected."

### [1:30–2:00] Turn 3 — Malware link detection
- User types: "Block this email too. The attachment link is http://dl.malware-drop.xyz/invoice.exe"
- Agent: finds TI-005 and TI-006 (malware distribution), POL-002, proceeds.
- Narration: "A known malware dropper — two threat-intel hits, policy POL-002, block authorized."

### [2:00–2:30] Turn 4 — BEC requires human review
- User types: "What should I do with an email from cfo-wiring-request.com asking for a wire transfer?"
- Agent: finds TI-007 (BEC domain), POL-003 requires human review.
- Decision panel: verdict: confirm — escalate to analyst
- Narration: "Business email compromise. The policy always requires a human analyst for
  wire-fraud scenarios — the decider returns requires_review and the action is held."

### [2:30–2:50] Benchmark and architecture
- Screen: submission/bench/results.md — 88.1% accuracy, 100% when confident
- Narration: "On a 14-case held-out test set, Strands Decider 2B answered 88% of questions
  correctly, and 100% of the cases it was confident about. The 45% of uncertain cases were
  routed to human review — exactly the right conservative behavior for security decisions."

### [2:50–3:00] Conclusion
- Screen: architecture overview (from submission/README.md Mermaid diagram)
- Narration: "SENTINEL AI: explainable security triage with Strands Decider 2B and
  Amazon Bedrock. Built with the AWS User Group Madurai Strands Decider hackathon kit."

---

## Current video status

The existing `demo.mp4` (91 seconds) contains the original kit store-support demo and is
preserved as-is. To record the SENTINEL AI demo:

1. Restore AWS Bedrock credentials: run `.\kit.cmd aws-login` in the terminal.
2. Start the demo UI: `.\kit.cmd demo-bg`
3. Record the four turns above against the live agent.
4. Run `.\kit.cmd video` to add slides and narration via Amazon Polly.
5. Verify duration < 180 seconds.
