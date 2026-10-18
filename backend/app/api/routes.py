"""FastAPI route definitions for TraceGuard."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from app.agents.workflow import run_investigation
from app.api.models import (
    AlertSummary,
    GraphStatsResponse,
    InvestigationResponse,
    RiskScoreResponse,
    ScoreFactor,
    VisualizationResponse,
)
from app.graph import repository
from app.graph.connection import get_graph

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get("/alerts", response_model=list[AlertSummary])
async def list_alerts() -> list[dict]:
    """List all security alerts from the graph."""
    try:
        alerts = repository.list_alerts()
        return alerts
    except Exception as e:
        logger.error("Failed to list alerts: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/{alert_id}", response_model=dict)
async def get_alert(alert_id: str) -> dict:
    """Get a single alert with its graph context."""
    ctx = repository.get_alert_context(alert_id)
    if not ctx.get("alert"):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return ctx


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------

@router.post("/investigate/{alert_id}", response_model=InvestigationResponse)
async def investigate(alert_id: str) -> InvestigationResponse:
    """
    Run the full LangGraph investigation workflow for an alert.

    This is the core endpoint — it:
    1. Validates the alert
    2. Runs multi-hop graph queries
    3. Calculates a deterministic risk score
    4. Generates findings and recommendation
    5. Persists the investigation to FalkorDB
    6. Returns structured results + visualization data
    """
    try:
        state = run_investigation(alert_id)
    except Exception as e:
        logger.error("Investigation workflow failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Investigation failed: {e}")

    if state.error:
        raise HTTPException(status_code=404, detail=state.error)

    score_data = state.risk_score_data

    return InvestigationResponse(
        investigation_id=state.investigation_id,
        alert_id=state.alert_id,
        verdict=state.verdict,
        risk_score=RiskScoreResponse(
            score=score_data.get("score", 0),
            verdict=score_data.get("verdict", "UNKNOWN"),
            factors=[
                ScoreFactor(**f) for f in (score_data.get("factors") or [])
            ],
            uncertainties=score_data.get("uncertainties") or [],
            capped=score_data.get("capped", False),
        ),
        summary=state.summary,
        recommendation=state.recommendation,
        findings=state.findings,
        uncertainties=state.uncertainties,
        threat_paths=state.threat_paths.get("paths") or [],
        related_accounts=state.related_entities.get("related_accounts") or [],
        devices=state.device_data.get("devices") or [],
        previous_cases=state.previous_cases.get("previous_investigations") or [],
        visualization_data=state.visualization_data,
        error=state.error,
    )


@router.get("/investigations/{alert_id}/history")
async def get_investigation_history(alert_id: str) -> dict:
    """Retrieve past investigations for an alert."""
    result = repository.get_previous_investigations(alert_id)
    return result


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

@router.get("/visualize/{alert_id}", response_model=VisualizationResponse)
async def get_visualization(alert_id: str) -> dict:
    """Return graph nodes and edges for React Flow visualization."""
    try:
        data = repository.get_visualization_data(alert_id)
        return data
    except Exception as e:
        logger.error("Visualization query failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Graph stats
# ---------------------------------------------------------------------------

@router.get("/graph/stats", response_model=GraphStatsResponse)
async def graph_stats() -> dict:
    """Return node and relationship counts for the TraceGuard graph."""
    graph = get_graph()
    labels = ["Alert", "Account", "Device", "IP", "ThreatIndicator", "Investigation"]
    rel_types = ["ON_ACCOUNT", "USED_FROM", "ACCESSED", "CONNECTED_TO", "HAS_INDICATOR", "INVESTIGATED", "USED_EVIDENCE"]

    node_counts: dict[str, int] = {}
    for label in labels:
        try:
            r = graph.query(f"MATCH (n:{label}) RETURN count(n) AS cnt")
            node_counts[label] = r.result_set[0][0] if r.result_set else 0
        except Exception:
            node_counts[label] = 0

    rel_counts: dict[str, int] = {}
    for rel in rel_types:
        try:
            r = graph.query(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS cnt")
            rel_counts[rel] = r.result_set[0][0] if r.result_set else 0
        except Exception:
            rel_counts[rel] = 0

    return {
        "node_counts": node_counts,
        "relationship_counts": rel_counts,
        "total_nodes": sum(node_counts.values()),
        "total_relationships": sum(rel_counts.values()),
    }


# ---------------------------------------------------------------------------
# Seed data refresh (dev utility)
# ---------------------------------------------------------------------------

@router.post("/graph/reseed")
async def reseed_graph() -> dict:
    """Force re-seed the graph. Use only in development."""
    from app.graph.initializer import initialize_graph
    initialize_graph(force=True)
    return {"status": "ok", "message": "Graph re-seeded successfully"}
