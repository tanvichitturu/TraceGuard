"""
LangGraph investigation workflow for TraceGuard.

Workflow nodes (in order):
  1. validate_alert
  2. fetch_alert_context
  3. multi_hop_investigation
  4. expand_related_entities
  5. check_previous_investigations
  6. calculate_risk_score
  7. verify_findings
  8. generate_explanation
  9. save_investigation
  10. finalize

All graph queries are delegated to app.graph.repository — the LLM only
generates natural-language explanations from structured evidence.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any, Literal

from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from app.agents.scoring import calculate_risk, RiskScore
from app.graph import repository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------

class InvestigationState(BaseModel):
    """Typed state passed between LangGraph nodes."""

    alert_id: str
    error: str | None = None

    # Investigation data (populated as the graph runs)
    alert_context: dict[str, Any] = Field(default_factory=dict)
    threat_paths: dict[str, Any] = Field(default_factory=dict)
    related_entities: dict[str, Any] = Field(default_factory=dict)
    device_data: dict[str, Any] = Field(default_factory=dict)
    previous_cases: dict[str, Any] = Field(default_factory=dict)

    # Scoring
    risk_score_data: dict[str, Any] = Field(default_factory=dict)

    # Findings
    findings: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    verdict: str = ""
    recommendation: str = ""
    summary: str = ""

    # Output
    investigation_id: str = ""
    visualization_data: dict[str, Any] = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True


# ---------------------------------------------------------------------------
# LLM (optional) — falls back to deterministic if not configured
# ---------------------------------------------------------------------------

def _get_llm() -> Any | None:
    provider = os.getenv("LLM_PROVIDER", "deterministic").lower()
    if provider == "openai":
        key = os.getenv("OPENAI_API_KEY", "")
        if key:
            try:
                from langchain_openai import ChatOpenAI
                model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
                return ChatOpenAI(model=model, api_key=key, temperature=0.2)
            except Exception as e:
                logger.warning("Failed to initialize OpenAI LLM: %s", e)
    elif provider == "google":
        key = os.getenv("GOOGLE_API_KEY", "")
        if key:
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
                model = os.getenv("GOOGLE_MODEL", "gemini-1.5-flash")
                return ChatGoogleGenerativeAI(model=model, google_api_key=key, temperature=0.2)
            except Exception as e:
                logger.warning("Failed to initialize Google LLM: %s", e)
    return None


# ---------------------------------------------------------------------------
# Deterministic explanation generator (no LLM required)
# ---------------------------------------------------------------------------

def _deterministic_explanation(state: InvestigationState) -> tuple[str, str]:
    """
    Generate a human-readable summary and recommendation without an LLM.

    Returns (summary, recommendation).
    """
    alert = state.alert_context.get("alert") or {}
    account = state.alert_context.get("account") or {}
    score_data = state.risk_score_data
    verdict = state.verdict
    paths = state.threat_paths.get("paths") or []
    devices = state.device_data.get("devices") or []

    alert_type = alert.get("type", "Unknown")
    username = account.get("username", "Unknown user")
    score = score_data.get("score", 0)
    factors = score_data.get("factors") or []

    factor_lines = "\n".join(
        f"  • {f['name']} (+{f['points']} pts): {f['reason']}"
        for f in factors
    )

    ioc_types = list({p["indicator"].get("type", "?") for p in paths if p.get("indicator")})
    device_names = [d["device"].get("hostname", "?") for d in devices]

    summary = (
        f"[SIMULATED DATA] Investigation of {alert_type} alert for account '{username}'. "
        f"Risk score: {score}/100 — Verdict: {verdict}. "
        f"Found {len(paths)} threat path(s)"
        + (f" via indicators: {', '.join(ioc_types)}" if ioc_types else "")
        + (f". Involved devices: {', '.join(device_names)}" if device_names else "")
        + f". Evidence factors:\n{factor_lines}"
    )

    recommendations = {
        "CRITICAL": (
            "IMMEDIATE ACTION REQUIRED: Isolate the affected account and all associated devices. "
            "Revoke credentials and initiate IR playbook. Notify security leadership."
        ),
        "HIGH": (
            "Escalate to Tier-2 SOC. Suspend the account pending review. "
            "Preserve forensic artifacts and initiate containment."
        ),
        "MEDIUM": (
            "Assign to on-call analyst for investigation within 4 hours. "
            "Monitor the account for further anomalous activity. "
            "Verify with the account holder."
        ),
        "LOW": (
            "Log and monitor. Review at next scheduled security triage. "
            "No immediate action required unless additional signals emerge."
        ),
        "BENIGN": (
            "Likely a false positive. Close the alert after analyst verification. "
            "Consider tuning detection rule to reduce noise."
        ),
    }
    recommendation = recommendations.get(verdict, recommendations["MEDIUM"])

    return summary, recommendation


# ---------------------------------------------------------------------------
# Workflow nodes
# ---------------------------------------------------------------------------

def validate_alert(state: InvestigationState) -> InvestigationState:
    """Node 1 — Validate that the alert exists in the graph."""
    logger.info("[Node 1] Validating alert %s", state.alert_id)
    ctx = repository.get_alert_context(state.alert_id)
    if not ctx.get("alert"):
        return state.model_copy(update={"error": f"Alert '{state.alert_id}' not found in graph."})
    return state


def fetch_alert_context(state: InvestigationState) -> InvestigationState:
    """Node 2 — Retrieve alert and its directly connected account."""
    if state.error:
        return state
    logger.info("[Node 2] Fetching alert context for %s", state.alert_id)
    ctx = repository.get_alert_context(state.alert_id)
    return state.model_copy(update={"alert_context": ctx})


def multi_hop_investigation(state: InvestigationState) -> InvestigationState:
    """Node 3 — Trace Alert → Account → IP → ThreatIndicator."""
    if state.error:
        return state
    logger.info("[Node 3] Multi-hop investigation for %s", state.alert_id)
    paths = repository.investigate_threat_paths(state.alert_id)
    return state.model_copy(update={"threat_paths": paths})


def expand_related_entities(state: InvestigationState) -> InvestigationState:
    """Node 4 — Expand to related accounts and devices."""
    if state.error:
        return state
    logger.info("[Node 4] Expanding related entities for %s", state.alert_id)
    related = repository.find_related_accounts(state.alert_id)
    devices = repository.investigate_devices(state.alert_id)
    return state.model_copy(update={
        "related_entities": related,
        "device_data": devices,
    })


def check_previous_investigations(state: InvestigationState) -> InvestigationState:
    """Node 5 — Retrieve previous investigations for this alert."""
    if state.error:
        return state
    logger.info("[Node 5] Checking previous investigations for %s", state.alert_id)
    prev = repository.get_previous_investigations(state.alert_id)
    return state.model_copy(update={"previous_cases": prev})


def calculate_risk_score(state: InvestigationState) -> InvestigationState:
    """Node 6 — Deterministic risk scoring from graph evidence."""
    if state.error:
        return state
    logger.info("[Node 6] Calculating risk score for %s", state.alert_id)
    risk: RiskScore = calculate_risk(
        alert_context=state.alert_context,
        threat_paths=state.threat_paths,
        device_data=state.device_data,
        related_accounts=state.related_entities,
    )
    return state.model_copy(update={
        "risk_score_data": risk.to_dict(),
        "verdict": risk.verdict,
        "uncertainties": risk.uncertainties,
    })


def verify_findings(state: InvestigationState) -> InvestigationState:
    """
    Node 7 — Build an evidence-backed findings list.

    Each finding MUST reference returned graph data — no invented claims.
    """
    if state.error:
        return state
    logger.info("[Node 7] Verifying findings for %s", state.alert_id)

    findings: list[str] = []
    paths = state.threat_paths.get("paths") or []
    devices = state.device_data.get("devices") or []
    related = state.related_entities.get("related_accounts") or []
    alert = state.alert_context.get("alert") or {}
    account = state.alert_context.get("account") or {}

    username = account.get("username", "unknown")
    alert_type = alert.get("type", "unknown")

    if not paths and not devices:
        findings.append(
            f"Graph traversal found no threat paths or device connections for alert {state.alert_id}. "
            "Assessment is based on alert metadata only."
        )
    else:
        if not paths:
            findings.append(
                f"Graph traversal found no Alert → Account → IP → ThreatIndicator path for alert {state.alert_id}. "
                "No exfiltration endpoint or threat indicator was returned by the graph; the assessment does not infer one from the alert description."
            )

        for path in paths:
            ip = path.get("ip") or {}
            ioc = path.get("indicator") or {}
            findings.append(
                f"Account '{username}' accessed {alert_type.lower()} activity from "
                f"IP {ip.get('address')} (reputation: {ip.get('reputation')}), "
                f"which is associated with IOC {ioc.get('id')} "
                f"({ioc.get('type')}, confidence {float(ioc.get('confidence', 0)):.0%})."
            )

        for dev_entry in devices:
            dev = dev_entry.get("device") or {}
            status = dev.get("status", "UNKNOWN")
            if status in ("COMPROMISED", "SUSPICIOUS"):
                connected_ips = [
                    c["ip"].get("address") for c in dev_entry.get("connected_ips", []) if c.get("ip")
                ]
                findings.append(
                    f"Device '{dev.get('hostname')}' (criticality: {dev.get('criticality')}) "
                    f"has status {status}. "
                    + (f"Connected to IPs: {', '.join(connected_ips)}." if connected_ips else "")
                )

    if related:
        direct = [r for r in related if r.get("connection_type") == "DIRECT"]
        if direct:
            names = [r["account"].get("username", "?") for r in direct]
            findings.append(
                f"Accounts sharing the same IP: {', '.join(names)}. "
                "Shared infrastructure — not treated as independent evidence of compromise."
            )

    prev = state.previous_cases.get("previous_investigations") or []
    if prev:
        last = prev[0].get("investigation") or {}
        findings.append(
            f"Previous investigation {last.get('id')} found verdict '{last.get('verdict')}' "
            f"(score {last.get('risk_score')}) on {last.get('created_at')}."
        )

    return state.model_copy(update={"findings": findings})


def generate_explanation(state: InvestigationState) -> InvestigationState:
    """Node 8 — Generate human-readable summary (LLM or deterministic)."""
    if state.error:
        return state
    logger.info("[Node 8] Generating explanation for %s", state.alert_id)

    llm = _get_llm()

    if llm:
        try:
            findings_text = "\n".join(f"- {f}" for f in state.findings)
            score_data = state.risk_score_data
            factors_text = "\n".join(
                f"- {f['name']}: +{f['points']} ({f['reason']})"
                for f in (score_data.get("factors") or [])
            )
            uncertainties_text = "\n".join(
                f"- {u}" for u in state.uncertainties
            ) or "None"

            prompt = (
                "You are a senior security analyst writing an investigation summary. "
                "The data below is SIMULATED for a hackathon demo. "
                "DO NOT claim these are real attacks.\n\n"
                f"Alert ID: {state.alert_id}\n"
                f"Verdict: {state.verdict}\n"
                f"Risk Score: {score_data.get('score')}/100\n\n"
                f"Findings:\n{findings_text}\n\n"
                f"Risk Factors:\n{factors_text}\n\n"
                f"Uncertainties:\n{uncertainties_text}\n\n"
                "Write a concise 3-sentence investigation summary and a one-sentence "
                "recommended next action. Format as:\n"
                "SUMMARY: <summary>\nRECOMMENDATION: <recommendation>"
            )

            from langchain_core.messages import HumanMessage
            response = llm.invoke([HumanMessage(content=prompt)])
            text = response.content if hasattr(response, "content") else str(response)

            summary = recommendation = ""
            for line in text.split("\n"):
                if line.startswith("SUMMARY:"):
                    summary = line[len("SUMMARY:"):].strip()
                elif line.startswith("RECOMMENDATION:"):
                    recommendation = line[len("RECOMMENDATION:"):].strip()

            if summary and recommendation:
                return state.model_copy(update={"summary": summary, "recommendation": recommendation})

        except Exception as e:
            logger.warning("LLM generation failed, using deterministic fallback: %s", e)

    # Deterministic fallback
    summary, recommendation = _deterministic_explanation(state)
    return state.model_copy(update={"summary": summary, "recommendation": recommendation})


def save_investigation_node(state: InvestigationState) -> InvestigationState:
    """Node 9 — Persist the investigation to FalkorDB."""
    if state.error:
        return state
    logger.info("[Node 9] Saving investigation for %s", state.alert_id)

    # Collect IOC IDs from threat paths
    ioc_ids = list({
        p["indicator"]["id"]
        for p in state.threat_paths.get("paths", [])
        if p.get("indicator") and p["indicator"].get("id")
    })

    inv_id = repository.save_investigation(
        alert_id=state.alert_id,
        risk_score=state.risk_score_data.get("score", 0.0),
        verdict=state.verdict,
        recommendation=state.recommendation,
        summary=state.summary,
        evidence_ioc_ids=ioc_ids,
    )
    return state.model_copy(update={"investigation_id": inv_id})


def finalize(state: InvestigationState) -> InvestigationState:
    """Node 10 — Fetch visualization data and mark complete."""
    if state.error:
        return state
    logger.info("[Node 10] Finalizing investigation %s", state.investigation_id)
    viz = repository.get_visualization_data(state.alert_id, state.investigation_id)
    return state.model_copy(update={"visualization_data": viz})


# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------

def route_after_validate(state: InvestigationState) -> Literal["fetch_alert_context", "end_error"]:
    return "end_error" if state.error else "fetch_alert_context"


# ---------------------------------------------------------------------------
# Graph compilation
# ---------------------------------------------------------------------------

def build_workflow() -> Any:
    """Compile and return the LangGraph workflow."""
    graph = StateGraph(InvestigationState)

    # Register nodes
    graph.add_node("validate_alert", validate_alert)
    graph.add_node("fetch_alert_context", fetch_alert_context)
    graph.add_node("multi_hop_investigation", multi_hop_investigation)
    graph.add_node("expand_related_entities", expand_related_entities)
    graph.add_node("check_previous_investigations", check_previous_investigations)
    graph.add_node("calculate_risk_score", calculate_risk_score)
    graph.add_node("verify_findings", verify_findings)
    graph.add_node("generate_explanation", generate_explanation)
    graph.add_node("save_investigation_node", save_investigation_node)
    graph.add_node("finalize", finalize)

    # Entry point
    graph.set_entry_point("validate_alert")

    # Conditional edge after validation
    graph.add_conditional_edges(
        "validate_alert",
        route_after_validate,
        {
            "fetch_alert_context": "fetch_alert_context",
            "end_error": END,
        },
    )

    # Linear edges for the rest of the pipeline
    graph.add_edge("fetch_alert_context", "multi_hop_investigation")
    graph.add_edge("multi_hop_investigation", "expand_related_entities")
    graph.add_edge("expand_related_entities", "check_previous_investigations")
    graph.add_edge("check_previous_investigations", "calculate_risk_score")
    graph.add_edge("calculate_risk_score", "verify_findings")
    graph.add_edge("verify_findings", "generate_explanation")
    graph.add_edge("generate_explanation", "save_investigation_node")
    graph.add_edge("save_investigation_node", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()


# Singleton — compiled once at import time
investigation_workflow = build_workflow()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_investigation(alert_id: str) -> InvestigationState:
    """Run the full investigation workflow for a given alert ID."""
    initial_state = InvestigationState(alert_id=alert_id)
    final_state = investigation_workflow.invoke(initial_state)
    # LangGraph returns a dict when using Pydantic state — reconstruct
    if isinstance(final_state, dict):
        final_state = InvestigationState(**final_state)
    return final_state
