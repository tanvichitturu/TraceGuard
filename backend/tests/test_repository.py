"""
Integration tests for the graph repository.

These tests require a running FalkorDB instance. Skip if unavailable.
"""

from __future__ import annotations

import pytest

# Try to import — skip all tests in this module if falkordb unavailable
try:
    import falkordb
    FALKORDB_AVAILABLE = True
except ImportError:
    FALKORDB_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not FALKORDB_AVAILABLE, reason="falkordb package not installed"
)


@pytest.fixture(scope="module")
def seeded_graph():
    """Initialize a test graph with seed data."""
    import os
    os.environ.setdefault("FALKORDB_HOST", "localhost")
    os.environ.setdefault("FALKORDB_PORT", "6379")
    os.environ.setdefault("GRAPH_NAME", "traceguard_test")

    try:
        from app.graph.initializer import initialize_graph
        initialize_graph(force=True)
        yield
    except Exception as e:
        pytest.skip(f"FalkorDB not available: {e}")


class TestAlertContext:
    def test_get_known_alert(self, seeded_graph):
        from app.graph import repository
        ctx = repository.get_alert_context("ALT-001")
        assert ctx["alert"] is not None
        assert ctx["alert"]["id"] == "ALT-001"
        assert ctx["account"] is not None

    def test_get_unknown_alert_returns_none(self, seeded_graph):
        from app.graph import repository
        ctx = repository.get_alert_context("ALT-NONEXISTENT")
        assert ctx["alert"] is None


class TestThreatPaths:
    def test_alt001_has_threat_paths(self, seeded_graph):
        from app.graph import repository
        result = repository.investigate_threat_paths("ALT-001")
        assert result["path_count"] > 0
        path = result["paths"][0]
        assert "alert" in path
        assert "account" in path
        assert "ip" in path
        assert "indicator" in path

    def test_paths_contain_malicious_ip(self, seeded_graph):
        from app.graph import repository
        result = repository.investigate_threat_paths("ALT-001")
        ips = {p["ip"]["address"] for p in result["paths"]}
        assert "185.220.101.42" in ips


class TestRelatedAccounts:
    def test_related_accounts_for_alt001(self, seeded_graph):
        from app.graph import repository
        result = repository.find_related_accounts("ALT-001")
        assert isinstance(result["related_accounts"], list)
        # acc-india also used the same malicious IP
        usernames = {r["account"]["username"] for r in result["related_accounts"]}
        assert "ivan.contractor" in usernames

    def test_connection_types_are_valid(self, seeded_graph):
        from app.graph import repository
        result = repository.find_related_accounts("ALT-001")
        for r in result["related_accounts"]:
            assert r["connection_type"] in ("DIRECT", "INDIRECT")


class TestDevices:
    def test_devices_for_alt001(self, seeded_graph):
        from app.graph import repository
        result = repository.investigate_devices("ALT-001")
        assert result["device_count"] > 0
        device_hostnames = {d["device"]["hostname"] for d in result["devices"]}
        assert "ws-charlie-03" in device_hostnames or "dev-server-01" in device_hostnames


class TestVisualization:
    def test_viz_returns_nodes_and_edges(self, seeded_graph):
        from app.graph import repository
        result = repository.get_visualization_data("ALT-001")
        assert "nodes" in result
        assert "edges" in result
        assert len(result["nodes"]) > 0

    def test_viz_nodes_have_required_fields(self, seeded_graph):
        from app.graph import repository
        result = repository.get_visualization_data("ALT-001")
        for node in result["nodes"]:
            assert "id" in node
            assert "label" in node
            assert "data" in node


class TestSaveInvestigation:
    def test_save_and_retrieve(self, seeded_graph):
        from app.graph import repository
        inv_id = repository.save_investigation(
            alert_id="ALT-001",
            risk_score=75.0,
            verdict="HIGH",
            recommendation="Isolate account",
            summary="Test investigation",
            evidence_ioc_ids=["IOC-001"],
        )
        assert inv_id.startswith("INV-")

        prev = repository.get_previous_investigations("ALT-001")
        ids = {p["investigation"]["id"] for p in prev["previous_investigations"]}
        assert inv_id in ids
