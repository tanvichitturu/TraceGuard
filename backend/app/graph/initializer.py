"""
Graph initializer — idempotent seed that creates the TraceGuard schema.

Uses MERGE to ensure repeated runs produce no duplicate nodes or relationships.
"""

from __future__ import annotations

import logging
from typing import Any

from app.graph.connection import get_graph
from app.graph.seed_data import NODES, RELATIONSHIPS

logger = logging.getLogger(__name__)


def _props_to_cypher(props: dict[str, Any]) -> str:
    """Convert a props dict to an inline Cypher property string."""
    parts = []
    for k, v in props.items():
        if isinstance(v, str):
            escaped = v.replace("'", "\\'")
            parts.append(f"{k}: '{escaped}'")
        elif isinstance(v, bool):
            parts.append(f"{k}: {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            parts.append(f"{k}: {v}")
        else:
            parts.append(f"{k}: '{v}'")
    return "{" + ", ".join(parts) + "}"


def _node_id_field(label: str) -> str:
    return "address" if label == "IP" else "id"


def initialize_graph(force: bool = False) -> None:
    """
    Idempotently seed the TraceGuard graph.

    Parameters
    ----------
    force:
        If True, drop and recreate the graph. Use only in tests.
    """
    graph = get_graph()

    if force:
        try:
            graph.delete()
            logger.warning("Graph deleted for forced re-initialization.")
        except Exception:
            pass

    # Check if already initialized
    try:
        result = graph.query("MATCH (a:Alert) RETURN count(a) AS cnt")
        if result.result_set and result.result_set[0][0] > 0 and not force:
            logger.info("Graph already initialized — skipping seed.")
            return
    except Exception:
        pass  # Graph may not exist yet

    logger.info("Seeding TraceGuard graph …")

    # Create nodes
    for label, node_list in NODES.items():
        id_field = _node_id_field(label)
        for node in node_list:
            id_value = node[id_field]
            props_str = _props_to_cypher(node)
            q = (
                f"MERGE (n:{label} {{{id_field}: '{id_value}'}})"
                f" ON CREATE SET n = {props_str}"
                f" ON MATCH SET n += {props_str}"
            )
            graph.query(q)

    logger.info("Nodes created.")

    # Create relationships
    for (
        from_label, from_id_field, from_id,
        rel_type,
        to_label, to_id_field, to_id,
        rel_props,
    ) in RELATIONSHIPS:
        rel_props_str = _props_to_cypher(rel_props) if rel_props else "{}"
        q = (
            f"MATCH (a:{from_label} {{{from_id_field}: '{from_id}'}})"
            f" MATCH (b:{to_label} {{{to_id_field}: '{to_id}'}})"
            f" MERGE (a)-[r:{rel_type}]->(b)"
            f" ON CREATE SET r = {rel_props_str}"
            f" ON MATCH SET r += {rel_props_str}"
        )
        graph.query(q)

    logger.info("Relationships created.")

    # Create indexes for fast lookups
    _create_indexes(graph)

    logger.info("Graph initialization complete.")


def _create_indexes(graph: Any) -> None:
    """Create indexes on commonly queried properties."""
    index_defs = [
        ("Alert", "id"),
        ("Account", "id"),
        ("Device", "id"),
        ("IP", "address"),
        ("ThreatIndicator", "id"),
        ("Investigation", "id"),
        ("Investigation", "alert_id"),
    ]
    for label, prop in index_defs:
        try:
            graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
        except Exception:
            pass  # Index may already exist
