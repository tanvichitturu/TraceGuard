"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    falkordb_host: str = "localhost"
    falkordb_port: int = 6379
    graph_name: str = "traceguard"
    log_level: str = "INFO"

    # LLM configuration — all optional
    llm_provider: str = "deterministic"  # "openai" | "google" | "deterministic"
    openai_api_key: str = ""
    google_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    google_model: str = "gemini-1.5-flash"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
