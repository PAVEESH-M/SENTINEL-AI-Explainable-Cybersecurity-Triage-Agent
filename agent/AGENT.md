# Use case

- **Pitch:** SENTINEL AI is an explainable cybersecurity triage agent that investigates suspicious
  emails and alerts, identifies phishing and social-engineering attempts, and recommends safe
  actions — with Strands Decider 2B gating every consequential response so the LLM can never
  act on unverified evidence or without explicit user authorization.
- **Who it is for:** students, small businesses, and security analysts who need to triage
  suspicious messages quickly without blindly trusting an LLM verdict.
- **Features:**
  - submit a suspicious email or alert in plain language;
  - search a synthetic threat-intelligence dataset for matching domains and URLs;
  - retrieve applicable security policies for the detected threat type;
  - Amazon Bedrock generates a structured investigation summary and proposes a response action;
  - before any consequential action (quarantine, block, escalate), Strands Decider 2B checks
    whether the proposed action is authorized by the user's request, grounded in the available
    evidence, and within the stated security policy scope;
  - uncertain, low-confidence, or policy-violating proposals go to human review instead;
  - a live decision panel shows each question's probability, the verdict, and the evidence that
    drove it — making the decision fully explainable;
  - an audit log records every proposed, approved, and blocked action;
  - deployed on Amazon Bedrock AgentCore Runtime.
- **The decision handed to Strands Decider 2B:** before a security triage action is taken, is
  it explicitly authorized by the user, grounded in verified evidence from the investigation,
  and within the scope of the applicable security policy? (`#guardrails`)
- **Why a decision model:** the check runs on every proposed action; it must be fast, cheap,
  and return calibrated probabilities the code can branch on — not a second expensive LLM call
  that could itself be manipulated by prompt-injection content in the suspicious message.
- **Amazon Bedrock:** the investigation reasoning and triage summary (Amazon Nova via UGMDU).

Built with the AWS User Group Madurai Strands Decider hackathon kit.
