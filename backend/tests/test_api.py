"""API response regressions for investigation findings."""

import asyncio

from app.agents.workflow import InvestigationState
from app.api import routes


def test_investigation_response_preserves_missing_path_finding(monkeypatch):
    expected_finding = (
        "Graph traversal found no Alert → Account → IP → ThreatIndicator path for alert ALT-002. "
        "No exfiltration endpoint or threat indicator was returned by the graph; "
        "the assessment does not infer one from the alert description."
    )
    state = InvestigationState(
        alert_id="ALT-002",
        investigation_id="INV-TEST",
        verdict="MEDIUM",
        risk_score_data={
            "score": 48,
            "verdict": "MEDIUM",
            "factors": [],
            "uncertainties": [],
            "capped": False,
        },
        findings=[expected_finding],
        visualization_data={},
    )
    monkeypatch.setattr(routes, "run_investigation", lambda _alert_id: state)

    response = asyncio.run(routes.investigate("ALT-002"))

    assert expected_finding in response.findings