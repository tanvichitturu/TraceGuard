"""Pydantic response models for the API."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class AlertSummary(BaseModel):
    id: str
    type: str
    timestamp: str
    severity: str
    status: str
    description: str
    account_username: str | None = None
    account_department: str | None = None


class ScoreFactor(BaseModel):
    name: str
    points: float
    reason: str
    evidence_ref: str | None = None


class RiskScoreResponse(BaseModel):
    score: float
    verdict: str
    factors: list[ScoreFactor]
    uncertainties: list[str]
    capped: bool


class InvestigationResponse(BaseModel):
    investigation_id: str
    alert_id: str
    verdict: str
    risk_score: RiskScoreResponse
    summary: str
    recommendation: str
    findings: list[str]
    uncertainties: list[str]
    threat_paths: list[dict[str, Any]]
    related_accounts: list[dict[str, Any]]
    devices: list[dict[str, Any]]
    previous_cases: list[dict[str, Any]]
    visualization_data: dict[str, Any]
    error: str | None = None


class VisualizationResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class GraphStatsResponse(BaseModel):
    node_counts: dict[str, int]
    relationship_counts: dict[str, int]
    total_nodes: int
    total_relationships: int
