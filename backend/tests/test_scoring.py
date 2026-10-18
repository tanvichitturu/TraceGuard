"""
Tests for the risk scoring engine.

These tests do NOT require a FalkorDB connection — they test the pure
scoring logic with mock graph data.
"""

from __future__ import annotations

import pytest
from app.agents.scoring import calculate_risk, WEIGHTS


def _make_alert_context(severity: str = "HIGH", alert_type: str = "BruteForce") -> dict:
    return {
        "alert": {"id": "ALT-TEST", "type": alert_type, "severity": severity},
        "account": {"id": "acc-test", "username": "test.user"},
    }


def _make_path(ip_reputation: str, ioc_confidence: float, ioc_id: str = "IOC-T1") -> dict:
    return {
        "alert": {"id": "ALT-TEST"},
        "account": {"id": "acc-test", "username": "test.user"},
        "ip": {"address": "1.2.3.4", "reputation": ip_reputation},
        "indicator": {"id": ioc_id, "type": "TestIOC", "source": "TestDB", "confidence": ioc_confidence},
        "ip_relationship": {"observed_at": "2026-01-01"},
        "ioc_relationship": {"observed_at": "2026-01-01"},
    }


def _make_path_for(ip_address: str, ip_reputation: str, ioc_confidence: float, ioc_id: str) -> dict:
    path = _make_path(ip_reputation, ioc_confidence, ioc_id)
    path["ip"]["address"] = ip_address
    return path


def _make_device(criticality: str, status: str) -> dict:
    return {
        "device": {"id": "dev-001", "hostname": "test-host", "criticality": criticality, "status": status},
        "account": {"id": "acc-test"},
        "access_relationship": {},
        "connected_ips": [],
    }


class TestScoringBaseline:
    def test_low_severity_no_paths_is_low_risk(self):
        ctx = _make_alert_context(severity="LOW")
        result = calculate_risk(ctx, {"paths": []}, {"devices": []}, {"related_accounts": []})
        assert result.score <= 20
        assert result.verdict in ("LOW", "BENIGN")

    def test_critical_severity_adds_30_points(self):
        ctx = _make_alert_context(severity="CRITICAL")
        result = calculate_risk(ctx, {"paths": []}, {"devices": []}, {"related_accounts": []})
        assert any(f.name == "Alert Severity" and f.points == WEIGHTS["severity_critical"] for f in result.factors)

    def test_high_severity_adds_25_points(self):
        ctx = _make_alert_context(severity="HIGH")
        result = calculate_risk(ctx, {"paths": []}, {"devices": []}, {"related_accounts": []})
        assert any(f.name == "Alert Severity" and f.points == WEIGHTS["severity_high"] for f in result.factors)


class TestScoringThreatPaths:
    def test_malicious_ip_adds_points(self):
        ctx = _make_alert_context()
        paths = {"paths": [_make_path("MALICIOUS", 0.95)]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        assert any(f.name == "Malicious IP" for f in result.factors)
        assert result.score > WEIGHTS["severity_high"]

    def test_high_confidence_ioc_adds_30_points(self):
        ctx = _make_alert_context()
        paths = {"paths": [_make_path("SUSPICIOUS", 0.95, "IOC-HC")]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        assert any(f.name == "High-Confidence IOC" and f.points == WEIGHTS["high_confidence_ioc"] for f in result.factors)

    def test_low_confidence_ioc_adds_uncertainty(self):
        ctx = _make_alert_context()
        paths = {"paths": [_make_path("CLEAN", 0.55, "IOC-LC")]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        assert len(result.uncertainties) > 0

    def test_multiple_paths_give_multi_hop_bonus(self):
        ctx = _make_alert_context()
        paths = {"paths": [
            _make_path_for("1.2.3.4", "MALICIOUS", 0.95, "IOC-A"),
            _make_path_for("5.6.7.8", "SUSPICIOUS", 0.80, "IOC-B"),
        ]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        assert any(f.name == "Multi-Hop Evidence" for f in result.factors)

    def test_duplicate_ioc_counted_once(self):
        ctx = _make_alert_context()
        # Same IOC ID twice — should only score once
        paths = {"paths": [
            _make_path("MALICIOUS", 0.95, "IOC-SAME"),
            _make_path("MALICIOUS", 0.95, "IOC-SAME"),
        ]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        ioc_factors = [f for f in result.factors if "IOC" in f.name]
        assert len(ioc_factors) == 1

    def test_duplicate_ip_reputation_counted_once(self):
        ctx = _make_alert_context()
        paths = {"paths": [
            _make_path_for("198.51.100.23", "MALICIOUS", 0.95, "IOC-A"),
            _make_path_for("198.51.100.23", "MALICIOUS", 0.75, "IOC-B"),
        ]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        ip_factors = [f for f in result.factors if f.name == "Malicious IP"]
        assert len(ip_factors) == 1

    def test_correlated_iocs_on_same_ip_use_strongest_confidence(self):
        ctx = _make_alert_context()
        paths = {"paths": [
            _make_path_for("198.51.100.23", "MALICIOUS", 0.98, "IOC-STRONG"),
            _make_path_for("198.51.100.23", "MALICIOUS", 0.75, "IOC-WEAKER"),
        ]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        ioc_factors = [f for f in result.factors if "Confidence IOC" in f.name]
        assert len(ioc_factors) == 1
        assert ioc_factors[0].evidence_ref == "IOC-STRONG"

    def test_repeated_same_ip_is_not_multi_hop_evidence(self):
        ctx = _make_alert_context()
        paths = {"paths": [
            _make_path_for("198.51.100.23", "MALICIOUS", 0.98, "IOC-A"),
            _make_path_for("198.51.100.23", "MALICIOUS", 0.75, "IOC-B"),
        ]}
        result = calculate_risk(ctx, paths, {"devices": []}, {"related_accounts": []})
        assert not any(f.name == "Multi-Hop Evidence" for f in result.factors)


class TestScoringDevices:
    def test_compromised_high_device_adds_points(self):
        ctx = _make_alert_context()
        devices = {"devices": [_make_device("HIGH", "COMPROMISED")]}
        result = calculate_risk(ctx, {"paths": []}, devices, {"related_accounts": []})
        assert any(f.name == "Compromised Device" for f in result.factors)

    def test_healthy_device_does_not_add_points(self):
        ctx = _make_alert_context()
        devices = {"devices": [_make_device("HIGH", "HEALTHY")]}
        result = calculate_risk(ctx, {"paths": []}, devices, {"related_accounts": []})
        assert not any(f.name in ("Compromised Device", "Suspicious Device") for f in result.factors)


class TestScoringCap:
    def test_score_never_exceeds_100(self):
        ctx = _make_alert_context(severity="CRITICAL", alert_type="LateralMovement")
        paths = {"paths": [
            _make_path("MALICIOUS", 0.99, "IOC-X"),
            _make_path("MALICIOUS", 0.98, "IOC-Y"),
            _make_path("MALICIOUS", 0.97, "IOC-Z"),
        ]}
        devices = {"devices": [
            _make_device("CRITICAL", "COMPROMISED"),
            _make_device("HIGH", "COMPROMISED"),
        ]}
        result = calculate_risk(ctx, paths, devices, {"related_accounts": []})
        assert result.score <= 100
        assert result.capped


class TestVerdicts:
    @pytest.mark.parametrize("score,expected", [
        (85, "CRITICAL"),
        (65, "HIGH"),
        (40, "MEDIUM"),
        (20, "LOW"),
        (5, "BENIGN"),
    ])
    def test_verdict_thresholds(self, score: float, expected: str):
        from app.agents.scoring import _verdict
        assert _verdict(score) == expected


class TestSeedAlertRegressions:
    """Regression coverage for the evidence profiles shown in the dashboard."""

    def test_alt001_scores_below_cap_after_correlated_ioc_deduplication(self):
        result = calculate_risk(
            {"alert": {"id": "ALT-001", "type": "BruteForce", "severity": "HIGH"}},
            {"paths": [
                _make_path_for("185.220.101.42", "MALICIOUS", 0.95, "IOC-001"),
                _make_path_for("185.220.101.42", "MALICIOUS", 0.88, "IOC-006"),
            ]},
            {"devices": [_make_device("HIGH", "COMPROMISED")]},
            {"related_accounts": []},
        )
        assert result.score == 93
        assert result.verdict == "CRITICAL"
        assert not any(f.name == "Multi-Hop Evidence" for f in result.factors)

    def test_alt002_description_does_not_create_unsupported_exfiltration_evidence(self):
        result = calculate_risk(
            {"alert": {
                "id": "ALT-002",
                "type": "DataExfiltration",
                "severity": "CRITICAL",
                "description": "Unusual outbound data transfer of 4.2 GB",
            }},
            {"paths": []},
            {"devices": [_make_device("HIGH", "COMPROMISED")]},
            {"related_accounts": []},
        )
        assert result.score == 48
        assert result.verdict == "MEDIUM"
        assert not any("exfil" in f.name.lower() or "exfil" in f.reason.lower() for f in result.factors)

    @pytest.mark.parametrize("alert_id,severity,alert_type,paths,devices,expected_score,expected_verdict", [
        ("ALT-003", "HIGH", "PrivilegeEscalation", [_make_path_for("203.0.113.77", "SUSPICIOUS", 0.65, "IOC-005")], [], 41, "MEDIUM"),
        ("ALT-005", "LOW", "AnomalousLogin", [], [], 5, "BENIGN"),
        ("ALT-006", "CRITICAL", "MalwareDetected", [
            _make_path_for("198.51.100.23", "MALICIOUS", 0.98, "IOC-003"),
            _make_path_for("198.51.100.23", "MALICIOUS", 0.75, "IOC-007"),
        ], [
            _make_device("MEDIUM", "SUSPICIOUS"),
            _make_device("HIGH", "COMPROMISED"),
            _make_device("HIGH", "SUSPICIOUS"),
        ], 100, "CRITICAL"),
    ])
    def test_remaining_observed_alert_scores(self, alert_id, severity, alert_type, paths, devices, expected_score, expected_verdict):
        result = calculate_risk(
            {"alert": {"id": alert_id, "type": alert_type, "severity": severity}},
            {"paths": paths},
            {"devices": devices},
            {"related_accounts": []},
        )
        assert result.score == expected_score
        assert result.verdict == expected_verdict
