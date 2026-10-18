"""
TraceGuard Graph Repository

All FalkorDB interactions live here. The LangGraph workflow calls these
functions exclusively — the LLM never writes or executes raw Cypher.

Each function returns typed dicts / lists that are safe for JSON serialization.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.graph.connection import get_graph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _row_to_dict(result_set: list, header: list[str]) -> list[dict[str, Any]]:
    """Convert a FalkorDB result_set to a list of dicts."""
    rows = []
    for row in result_set:
        d: dict[str, Any] = {}
        for i, col in enumerate(header):
            val = row[i]
            if hasattr(val, "properties"):
                # Node or edge object
                d[col] = dict(val.properties)
            elif hasattr(val, "__dict__"):
                d[col] = str(val)
            else:
                d[col] = val
        rows.append(d)
    return rows


def _node_props(node: Any) -> dict[str, Any]:
    if node is None:
        return {}
    if hasattr(node, "properties"):
        return dict(node.properties)
    if isinstance(node, dict):
        return node
    return {}


def _rel_props(rel: Any) -> dict[str, Any]:
    if rel is None:
        return {}
    if hasattr(rel, "properties"):
        return dict(rel.properties)
    if isinstance(rel, dict):
        return rel
    return {}


# ---------------------------------------------------------------------------
# A. Alert context
# ---------------------------------------------------------------------------

def get_alert_context(alert_id: str) -> dict[str, Any]:
    """
    Retrieve an alert and its directly connected account.

    Returns:
        {
            "alert": {...},
            "account": {...} | None,
            "relationship": {...} | None
        }
    """
    graph = get_graph()
    q = """
        MATCH (a:Alert {id: $alert_id})
        OPTIONAL MATCH (a)-[r:ON_ACCOUNT]->(acc:Account)
        RETURN a AS alert, acc AS account, r AS rel
    """
    result = graph.query(q, {"alert_id": alert_id})
    if not result.result_set:
        return {"alert": None, "account": None, "relationship": None}

    row = result.result_set[0]
    return {
        "alert": _node_props(row[0]),
        "account": _node_props(row[1]) if len(row) > 1 else None,
        "relationship": _rel_props(row[2]) if len(row) > 2 else None,
    }


# ---------------------------------------------------------------------------
# B. Multi-hop threat investigation
# ---------------------------------------------------------------------------

def investigate_threat_paths(alert_id: str) -> dict[str, Any]:
    """
    Trace: Alert → Account → IP → ThreatIndicator

    Returns the full path and all entity properties.
    Each returned path is: alert → account → ip → indicator
    """
    graph = get_graph()
    q = """
        MATCH (alert:Alert {id: $alert_id})-[:ON_ACCOUNT]->(acc:Account)
        MATCH (acc)-[r_ip:USED_FROM]->(ip:IP)
        MATCH (ip)-[r_ioc:HAS_INDICATOR]->(ioc:ThreatIndicator)
        RETURN
            alert   AS alert,
            acc     AS account,
            ip      AS ip,
            ioc     AS indicator,
            r_ip    AS ip_rel,
            r_ioc   AS ioc_rel
        ORDER BY ioc.confidence DESC
    """
    result = graph.query(q, {"alert_id": alert_id})
    paths = []
    for row in result.result_set:
        paths.append({
            "alert": _node_props(row[0]),
            "account": _node_props(row[1]),
            "ip": _node_props(row[2]),
            "indicator": _node_props(row[3]),
            "ip_relationship": _rel_props(row[4]),
            "ioc_relationship": _rel_props(row[5]),
            "path_label": f"{row[1].properties.get('username','?')} → {row[2].properties.get('address','?')} → {row[3].properties.get('type','?')}",
        })
    return {"paths": paths, "path_count": len(paths)}


# ---------------------------------------------------------------------------
# C. Related account discovery
# ---------------------------------------------------------------------------

def find_related_accounts(alert_id: str) -> dict[str, Any]:
    """
    Find other accounts sharing an IP or ThreatIndicator with the alert's account.

    Distinguishes:
    - DIRECT: shares an IP directly used by the alert account
    - INDIRECT: shares a ThreatIndicator via a different IP
    """
    graph = get_graph()

    # Direct: shared IP
    q_direct = """
        MATCH (alert:Alert {id: $alert_id})-[:ON_ACCOUNT]->(primary:Account)
        MATCH (primary)-[:USED_FROM]->(ip:IP)<-[:USED_FROM]-(other:Account)
        WHERE other.id <> primary.id
        RETURN other AS account, ip AS shared_ip, 'DIRECT' AS connection_type
    """
    result_direct = graph.query(q_direct, {"alert_id": alert_id})

    # Indirect: shared threat indicator via any IP
    q_indirect = """
        MATCH (alert:Alert {id: $alert_id})-[:ON_ACCOUNT]->(primary:Account)
        MATCH (primary)-[:USED_FROM]->(ip1:IP)-[:HAS_INDICATOR]->(ioc:ThreatIndicator)
        MATCH (ioc)<-[:HAS_INDICATOR]-(ip2:IP)<-[:USED_FROM]-(other:Account)
        WHERE other.id <> primary.id AND ip2.address <> ip1.address
        RETURN other AS account, ioc AS shared_indicator, 'INDIRECT' AS connection_type
    """
    result_indirect = graph.query(q_indirect, {"alert_id": alert_id})

    related: list[dict] = []
    seen_ids: set[str] = set()

    for row in result_direct.result_set:
        acc_props = _node_props(row[0])
        acc_id = acc_props.get("id", "")
        if acc_id not in seen_ids:
            seen_ids.add(acc_id)
            related.append({
                "account": acc_props,
                "shared_entity": _node_props(row[1]),
                "shared_entity_type": "IP",
                "connection_type": "DIRECT",
            })

    for row in result_indirect.result_set:
        acc_props = _node_props(row[0])
        acc_id = acc_props.get("id", "")
        if acc_id not in seen_ids:
            seen_ids.add(acc_id)
            related.append({
                "account": acc_props,
                "shared_entity": _node_props(row[1]),
                "shared_entity_type": "ThreatIndicator",
                "connection_type": "INDIRECT",
            })

    return {"related_accounts": related, "count": len(related)}


# ---------------------------------------------------------------------------
# D. Device investigation
# ---------------------------------------------------------------------------

def investigate_devices(alert_id: str) -> dict[str, Any]:
    """
    Trace: Alert → Account → Device → IP

    Returns device criticality, status, connected IPs, and timing.
    """
    graph = get_graph()
    q = """
        MATCH (alert:Alert {id: $alert_id})-[:ON_ACCOUNT]->(acc:Account)
        MATCH (acc)-[r_acc:ACCESSED]->(dev:Device)
        OPTIONAL MATCH (dev)-[r_dev:CONNECTED_TO]->(ip:IP)
        RETURN
            acc     AS account,
            dev     AS device,
            ip      AS connected_ip,
            r_acc   AS access_rel,
            r_dev   AS connection_rel
        ORDER BY dev.criticality DESC
    """
    result = graph.query(q, {"alert_id": alert_id})

    # Group by device
    devices: dict[str, dict] = {}
    for row in result.result_set:
        dev_props = _node_props(row[1])
        dev_id = dev_props.get("id", "unknown")
        if dev_id not in devices:
            devices[dev_id] = {
                "device": dev_props,
                "account": _node_props(row[0]),
                "access_relationship": _rel_props(row[3]),
                "connected_ips": [],
            }
        ip_props = _node_props(row[2])
        if ip_props:
            devices[dev_id]["connected_ips"].append({
                "ip": ip_props,
                "connection_rel": _rel_props(row[4]),
            })

    return {"devices": list(devices.values()), "device_count": len(devices)}


# ---------------------------------------------------------------------------
# E. Previous investigation retrieval
# ---------------------------------------------------------------------------

def get_previous_investigations(alert_id: str) -> dict[str, Any]:
    """Retrieve any prior investigations for this alert."""
    graph = get_graph()
    q = """
        MATCH (inv:Investigation {alert_id: $alert_id})
        OPTIONAL MATCH (inv)-[:USED_EVIDENCE]->(ioc:ThreatIndicator)
        RETURN inv AS investigation, collect(ioc) AS evidence
        ORDER BY inv.created_at DESC
        LIMIT 5
    """
    result = graph.query(q, {"alert_id": alert_id})
    investigations = []
    for row in result.result_set:
        inv = _node_props(row[0])
        evidence = [_node_props(e) for e in (row[1] or [])]
        investigations.append({"investigation": inv, "evidence": evidence})

    return {"previous_investigations": investigations, "count": len(investigations)}


# ---------------------------------------------------------------------------
# F. Save investigation
# ---------------------------------------------------------------------------

def save_investigation(
    alert_id: str,
    risk_score: float,
    verdict: str,
    recommendation: str,
    summary: str,
    evidence_ioc_ids: list[str],
) -> str:
    """
    Persist an investigation result to FalkorDB.

    Returns the new investigation ID.
    """
    graph = get_graph()
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    created_at = datetime.now(timezone.utc).isoformat()

    # Create the Investigation node
    graph.query(
        """
        MERGE (inv:Investigation {id: $id})
        ON CREATE SET
            inv.alert_id = $alert_id,
            inv.risk_score = $risk_score,
            inv.verdict = $verdict,
            inv.created_at = $created_at,
            inv.recommendation = $recommendation,
            inv.summary = $summary
        """,
        {
            "id": inv_id,
            "alert_id": alert_id,
            "risk_score": risk_score,
            "verdict": verdict,
            "created_at": created_at,
            "recommendation": recommendation,
            "summary": summary,
        },
    )

    # Link to Alert
    graph.query(
        """
        MATCH (inv:Investigation {id: $inv_id})
        MATCH (a:Alert {id: $alert_id})
        MERGE (inv)-[:INVESTIGATED]->(a)
        """,
        {"inv_id": inv_id, "alert_id": alert_id},
    )

    # Link to evidence indicators
    for ioc_id in evidence_ioc_ids:
        graph.query(
            """
            MATCH (inv:Investigation {id: $inv_id})
            MATCH (ioc:ThreatIndicator {id: $ioc_id})
            MERGE (inv)-[:USED_EVIDENCE]->(ioc)
            """,
            {"inv_id": inv_id, "ioc_id": ioc_id},
        )

    logger.info("Saved investigation %s for alert %s (score=%.1f)", inv_id, alert_id, risk_score)
    return inv_id


# ---------------------------------------------------------------------------
# G. Graph visualization data
# ---------------------------------------------------------------------------

def get_visualization_data(alert_id: str, investigation_id: str | None = None) -> dict[str, Any]:
    """
    Return nodes and edges for React Flow rendering.

    Covers: Alert → Account → IP → ThreatIndicator
             Account → Device → IP
    """
    graph = get_graph()

    # Collect all relevant nodes and edges
    q = """
        MATCH (alert:Alert {id: $alert_id})
        OPTIONAL MATCH (alert)-[r1:ON_ACCOUNT]->(acc:Account)
        OPTIONAL MATCH (acc)-[r2:USED_FROM]->(ip:IP)
        OPTIONAL MATCH (ip)-[r3:HAS_INDICATOR]->(ioc:ThreatIndicator)
        OPTIONAL MATCH (acc)-[r4:ACCESSED]->(dev:Device)
        OPTIONAL MATCH (dev)-[r5:CONNECTED_TO]->(dip:IP)
        RETURN
            alert, acc, ip, ioc, dev, dip,
            r1, r2, r3, r4, r5
    """
    result = graph.query(q, {"alert_id": alert_id})

    nodes_map: dict[str, dict] = {}
    edges: list[dict] = {}

    def add_node(label: str, obj: Any) -> str | None:
        props = _node_props(obj)
        if not props:
            return None
        node_id = props.get("id") or props.get("address") or props.get("hostname")
        if not node_id:
            return None
        key = f"{label}:{node_id}"
        if key not in nodes_map:
            nodes_map[key] = {"id": key, "label": label, "data": props, "type": label.lower()}
        return key

    def add_edge(source_key: str | None, target_key: str | None, rel_type: str, rel: Any) -> None:
        if not source_key or not target_key:
            return
        edge_id = f"{source_key}--{rel_type}-->{target_key}"
        if edge_id not in edges:
            edges[edge_id] = {
                "id": edge_id,
                "source": source_key,
                "target": target_key,
                "label": rel_type,
                "data": _rel_props(rel),
            }

    for row in result.result_set:
        alert_key = add_node("Alert", row[0])
        acc_key = add_node("Account", row[1])
        ip_key = add_node("IP", row[2])
        ioc_key = add_node("ThreatIndicator", row[3])
        dev_key = add_node("Device", row[4])
        dip_key = add_node("IP", row[5])

        add_edge(alert_key, acc_key, "ON_ACCOUNT", row[6])
        add_edge(acc_key, ip_key, "USED_FROM", row[7])
        add_edge(ip_key, ioc_key, "HAS_INDICATOR", row[8])
        add_edge(acc_key, dev_key, "ACCESSED", row[9])
        add_edge(dev_key, dip_key, "CONNECTED_TO", row[10])

    return {
        "nodes": list(nodes_map.values()),
        "edges": list(edges.values()),
    }


# ---------------------------------------------------------------------------
# H. List all alerts
# ---------------------------------------------------------------------------

def list_alerts() -> list[dict[str, Any]]:
    """Return all alerts with their connected account username."""
    graph = get_graph()
    q = """
        MATCH (a:Alert)
        OPTIONAL MATCH (a)-[:ON_ACCOUNT]->(acc:Account)
        RETURN a AS alert, acc AS account
        ORDER BY a.severity DESC, a.timestamp DESC
    """
    result = graph.query(q)
    alerts = []
    for row in result.result_set:
        alert_props = _node_props(row[0])
        acc_props = _node_props(row[1]) if len(row) > 1 else {}
        if acc_props:
            alert_props["account_username"] = acc_props.get("username")
            alert_props["account_department"] = acc_props.get("department")
        alerts.append(alert_props)
    return alerts
