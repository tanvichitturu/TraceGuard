"""FalkorDB connection manager — single shared connection per process."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator

import falkordb

from app.config import get_settings

logger = logging.getLogger(__name__)

_client: falkordb.FalkorDB | None = None


def get_client() -> falkordb.FalkorDB:
    """Return (or create) the global FalkorDB client."""
    global _client
    if _client is None:
        settings = get_settings()
        logger.info(
            "Connecting to FalkorDB at %s:%s",
            settings.falkordb_host,
            settings.falkordb_port,
        )
        _client = falkordb.FalkorDB(
    host=settings.falkordb_host,
    port=settings.falkordb_port,
    username=settings.falkordb_username,
    password=settings.falkordb_password or None,
    ssl=settings.falkordb_ssl,
)
    return _client


def get_graph() -> falkordb.Graph:
    """Return the named graph object."""
    settings = get_settings()
    client = get_client()
    return client.select_graph(settings.graph_name)


@contextmanager
def graph_context() -> Generator[falkordb.Graph, None, None]:
    """Context manager that yields the graph, swallowing transient errors gracefully."""
    try:
        yield get_graph()
    except Exception as exc:
        logger.error("FalkorDB error: %s", exc, exc_info=True)
        raise
