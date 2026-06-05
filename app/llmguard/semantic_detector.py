from __future__ import annotations

from functools import lru_cache

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.config import get_settings
from app.llmguard.risk_engine import StageSignal, signal

ATTACK_INTENTS = (
    "act as admin",
    "ignore role",
    "show all records",
    "retrieve internal data",
    "reveal hidden instructions",
    "use admin privileges",
    "bypass access control",
    "extract confidential documents",
)


class SemanticAttackDetector:
    def __init__(self, attack_intents: tuple[str, ...] = ATTACK_INTENTS) -> None:
        self.attack_intents = attack_intents
        self.settings = get_settings()
        self._vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
        self._intent_matrix = self._vectorizer.fit_transform(attack_intents)
        self._model = None
        self._intent_embeddings = None
        self._loaded_model = False

    def _load_model(self):
        if self._loaded_model:
            return self._model
        self._loaded_model = True
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(
                self.settings.semantic_model_name,
                device="cpu",
                local_files_only=self.settings.semantic_local_files_only,
            )
            self._intent_embeddings = self._model.encode(list(self.attack_intents), normalize_embeddings=True)
        except Exception:
            self._model = None
            self._intent_embeddings = None
        return self._model

    def inspect(self, text: str) -> StageSignal:
        normalized = " ".join(text.split())
        if not normalized:
            return signal("semantic_detector", score=0.0, reasons=["No text to inspect."])

        model = self._load_model()
        if model is not None and self._intent_embeddings is not None:
            query_embedding = model.encode([normalized], normalize_embeddings=True)
            similarities = cosine_similarity(query_embedding, self._intent_embeddings)[0]
            backend = "sentence-transformers"
        else:
            query_vector = self._vectorizer.transform([normalized])
            similarities = cosine_similarity(query_vector, self._intent_matrix)[0]
            backend = "lexical-semantic-fallback"

        score = float(np.max(similarities)) if similarities.size else 0.0
        index = int(np.argmax(similarities)) if similarities.size else 0
        matched = self.attack_intents[index] if similarities.size else ""
        if score >= 0.62:
            label = "malicious"
            action = "block"
        elif score >= 0.35:
            label = "suspicious"
            action = "sanitize"
        else:
            label = "safe"
            action = "allow"
        reasons = (
            [f"Semantic similarity matched attack intent '{matched}' using {backend}."]
            if label != "safe"
            else ["No semantic attack intent matched."]
        )
        return signal(
            "semantic_detector",
            label=label,
            action=action,
            score=score,
            reasons=reasons,
            threat_source="prompt" if label != "safe" else "none",
            metadata={"matched_intent": matched, "backend": backend},
        )


@lru_cache(maxsize=1)
def get_semantic_attack_detector() -> SemanticAttackDetector:
    return SemanticAttackDetector()


def inspect_semantic_intent(text: str) -> StageSignal:
    return get_semantic_attack_detector().inspect(text)
