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
    evaluation_dir: Path
    models_dir: Path
    logs_dir: Path
    db_path: Path
    vendor_dir: Path
    retrieval_index_dir: Path
    ml_dataset_path: Path
    evaluation_dataset_path: Path
    ml_model_dir: Path
    ml_model_path: Path
    ml_training_report_path: Path
    ollama_url: str
    ollama_model: str
    retrieval_min_score: float
    retrieval_top_k: int
    retrieval_chunk_size: int
    retrieval_chunk_overlap: int
    retrieval_chunk_sentence_window: int
    retrieval_chunk_sentence_overlap: int
    retrieval_batch_size: int
    retrieval_poisoned_score_penalty: float
    semantic_threshold: float
    semantic_model_name: str
    semantic_use_embeddings: bool
    semantic_local_files_only: bool
    ml_classifier_min_confidence: float
    hybrid_rule_weight: float
    hybrid_semantic_weight: float
    hybrid_ml_weight: float
    hybrid_safe_score_multiplier: float
    hybrid_suspicious_score_floor: float
    hybrid_malicious_score_floor: float
    hybrid_semantic_support_threshold: float
    suspicious_risk_threshold: float
    malicious_risk_threshold: float
    quarantine_risk_threshold: float
    block_risk_threshold: float


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
    evaluation_dir = _path_from_env("LLMGUARD_EVALUATION_DIR", data_dir / "evaluation")
    models_dir = _path_from_env("LLMGUARD_MODELS_DIR", base_dir / "models")
    logs_dir = _path_from_env("LLMGUARD_LOGS_DIR", base_dir / "logs")
    db_path = _path_from_env("LLMGUARD_DB_PATH", logs_dir / "llmguard.db")
    vendor_dir = _path_from_env("LLMGUARD_VENDOR_DIR", base_dir / ".vendor")
    retrieval_index_dir = _path_from_env(
        "LLMGUARD_RETRIEVAL_INDEX_DIR",
        data_dir / "semantic_index",
    )
    ml_model_dir = _path_from_env(
        "LLMGUARD_ML_MODEL_DIR",
        models_dir / "hybrid_firewall",
    )
    ml_dataset_path = _path_from_env(
        "LLMGUARD_ML_DATASET_PATH",
        data_dir / "firewall" / "training_dataset.jsonl",
    )
    evaluation_dataset_path = _path_from_env(
        "LLMGUARD_EVALUATION_DATASET_PATH",
        data_dir / "firewall" / "evaluation_dataset.jsonl",
    )
    ml_model_path = _path_from_env(
        "LLMGUARD_ML_MODEL_PATH",
        ml_model_dir / "logistic_regression.joblib",
    )
    ml_training_report_path = _path_from_env(
        "LLMGUARD_ML_REPORT_PATH",
        ml_model_dir / "training_report.json",
    )

    return Settings(
        base_dir=base_dir,
        docs_dir=docs_dir,
        data_dir=data_dir,
        evaluation_dir=evaluation_dir,
        models_dir=models_dir,
        logs_dir=logs_dir,
        db_path=db_path,
        vendor_dir=vendor_dir,
        retrieval_index_dir=retrieval_index_dir,
        ml_dataset_path=ml_dataset_path,
        evaluation_dataset_path=evaluation_dataset_path,
        ml_model_dir=ml_model_dir,
        ml_model_path=ml_model_path,
        ml_training_report_path=ml_training_report_path,
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
        retrieval_poisoned_score_penalty=float(
            os.getenv("LLMGUARD_RETRIEVAL_POISONED_SCORE_PENALTY", "0.08")
        ),
        semantic_threshold=float(os.getenv("LLMGUARD_SEMANTIC_THRESHOLD", "0.45")),
        semantic_model_name=os.getenv("LLMGUARD_SEMANTIC_MODEL", "all-MiniLM-L6-v2"),
        semantic_use_embeddings=_bool_from_env("LLMGUARD_USE_EMBEDDINGS", True),
        semantic_local_files_only=_bool_from_env("LLMGUARD_LOCAL_FILES_ONLY", True),
        ml_classifier_min_confidence=float(os.getenv("LLMGUARD_ML_MIN_CONFIDENCE", "0.45")),
        hybrid_rule_weight=float(os.getenv("LLMGUARD_HYBRID_RULE_WEIGHT", "0.20")),
        hybrid_semantic_weight=float(os.getenv("LLMGUARD_HYBRID_SEMANTIC_WEIGHT", "0.20")),
        hybrid_ml_weight=float(os.getenv("LLMGUARD_HYBRID_ML_WEIGHT", "0.60")),
        hybrid_safe_score_multiplier=float(
            os.getenv("LLMGUARD_HYBRID_SAFE_SCORE_MULTIPLIER", "0.45")
        ),
        hybrid_suspicious_score_floor=float(
            os.getenv("LLMGUARD_HYBRID_SUSPICIOUS_SCORE_FLOOR", "0.48")
        ),
        hybrid_malicious_score_floor=float(
            os.getenv("LLMGUARD_HYBRID_MALICIOUS_SCORE_FLOOR", "0.76")
        ),
        hybrid_semantic_support_threshold=float(
            os.getenv("LLMGUARD_HYBRID_SEMANTIC_SUPPORT_THRESHOLD", "0.40")
        ),
        suspicious_risk_threshold=float(os.getenv("LLMGUARD_SUSPICIOUS_RISK_THRESHOLD", "0.38")),
        malicious_risk_threshold=float(os.getenv("LLMGUARD_MALICIOUS_RISK_THRESHOLD", "0.72")),
        quarantine_risk_threshold=float(os.getenv("LLMGUARD_QUARANTINE_RISK_THRESHOLD", "0.82")),
        block_risk_threshold=float(os.getenv("LLMGUARD_BLOCK_RISK_THRESHOLD", "0.92")),
    )


def reset_settings_cache() -> None:
    get_settings.cache_clear()
