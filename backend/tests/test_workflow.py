"""Regression tests for evidence-grounded workflow findings."""

from app.agents.workflow import InvestigationState, verify_findings


def test_no_threat_path_is_explicit_when_device_evidence_exists():
    state = InvestigationState(
        alert_id="ALT-002",
        alert_context={
            "alert": {"type": "DataExfiltration"},
            "account": {"username": "alice.morgan"},
        },
        threat_paths={"paths": []},
        device_data={"devices": [{
            "device": {
                "hostname": "dev-server-01",
                "criticality": "HIGH",
                "status": "COMPROMISED",
            },
            "connected_ips": [],
        }]},
    )

    result = verify_findings(state)

    assert any("no Alert → Account → IP → ThreatIndicator path" in finding for finding in result.findings)
    assert any("does not infer one from the alert description" in finding for finding in result.findings)