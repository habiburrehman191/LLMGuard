from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    docs_dir: Path
    data_dir: Path
    logs_dir: Path
    db_path: Path
    vendor_dir: Path
    retrieval_index_dir: Path
    ollama_url: str
    ollama_model: str
    retrieval_min_score: float
    retrieval_top_k: int
    retrieval_chunk_size: int
    retrieval_chunk_overlap: int
    retrieval_chunk_sentence_window: int
    retrieval_chunk_sentence_overlap: int
    retrieval_batch_size: int
    semantic_threshold: float
    semantic_model_name: str
    semantic_use_embeddings: bool
    semantic_local_files_only: bool


def _path_from_env(env_name: str, default: Path) -> Path:
    raw_value = os.getenv(env_name)
    return Path(raw_value).expanduser() if raw_value else default


def _bool_from_env(env_name: str, default: bool) -> bool:
    raw_value = os.getenv(env_name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    base_dir = _path_from_env("LLMGUARD_BASE_DIR", BASE_DIR)
    docs_dir = _path_from_env("LLMGUARD_DOCS_DIR", base_dir / "docs")
    data_dir = _path_from_env("LLMGUARD_DATA_DIR", base_dir / "data")
    logs_dir = _path_from_env("LLMGUARD_LOGS_DIR", base_dir / "logs")
    db_path = _path_from_env("LLMGUARD_DB_PATH", logs_dir / "llmguard.db")
    vendor_dir = _path_from_env("LLMGUARD_VENDOR_DIR", base_dir / ".vendor")
    retrieval_index_dir = _path_from_env(
        "LLMGUARD_RETRIEVAL_INDEX_DIR",
        data_dir / "semantic_index",
    )

    return Settings(
        base_dir=base_dir,
        docs_dir=docs_dir,
        data_dir=data_dir,
        logs_dir=logs_dir,
        db_path=db_path,
        vendor_dir=vendor_dir,
        retrieval_index_dir=retrieval_index_dir,
        ollama_url=os.getenv("LLMGUARD_OLLAMA_URL", "http://localhost:11434/api/chat"),
        ollama_model=os.getenv("LLMGUARD_OLLAMA_MODEL", "vicuna"),
        retrieval_min_score=float(os.getenv("LLMGUARD_RETRIEVAL_MIN_SCORE", "0.05")),
        retrieval_top_k=int(os.getenv("LLMGUARD_RETRIEVAL_TOP_K", "4")),
        retrieval_chunk_size=int(os.getenv("LLMGUARD_RETRIEVAL_CHUNK_SIZE", "320")),
        retrieval_chunk_overlap=int(os.getenv("LLMGUARD_RETRIEVAL_CHUNK_OVERLAP", "1")),
        retrieval_chunk_sentence_window=int(
            os.getenv("LLMGUARD_RETRIEVAL_CHUNK_SENTENCE_WINDOW", "2")
        ),
        retrieval_chunk_sentence_overlap=int(
            os.getenv("LLMGUARD_RETRIEVAL_CHUNK_SENTENCE_OVERLAP", "1")
        ),
        retrieval_batch_size=int(os.getenv("LLMGUARD_RETRIEVAL_BATCH_SIZE", "16")),
        semantic_threshold=float(os.getenv("LLMGUARD_SEMANTIC_THRESHOLD", "0.45")),
        semantic_model_name=os.getenv("LLMGUARD_SEMANTIC_MODEL", "all-MiniLM-L6-v2"),
        semantic_use_embeddings=_bool_from_env("LLMGUARD_USE_EMBEDDINGS", False),
        semantic_local_files_only=_bool_from_env("LLMGUARD_LOCAL_FILES_ONLY", True),
    )


def reset_settings_cache() -> None:
    get_settings.cache_clear()
