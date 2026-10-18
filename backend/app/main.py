"""FastAPI application — entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.graph.initializer import initialize_graph
from app.api.routes import router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the graph on startup."""
    settings = get_settings()
    logger.info("TraceGuard backend starting — graph: %s", settings.graph_name)
    try:
        initialize_graph()
    except Exception as e:
        logger.error("Graph initialization failed: %s", e)
        logger.warning("Continuing without pre-seeded data — ensure FalkorDB is running.")
    yield
    logger.info("TraceGuard backend shutting down.")


app = FastAPI(
    title="TraceGuard API",
    description="Explainable threat investigation powered by FalkorDB + LangGraph",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the Next.js dev server and production build
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "traceguard-backend"}
