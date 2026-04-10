from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
import textwrap
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any

import numpy as np

from app.config import get_settings

SENTENCE_SPLIT_PATTERN = re.compile(r"(?<=[.!?])\s+")
PARAGRAPH_SPLIT_PATTERN = re.compile(r"\n\s*\n")


def _ensure_vendor_path() -> None:
    vendor_dir = get_settings().vendor_dir
    vendor_path = str(vendor_dir)
    if vendor_dir.exists() and vendor_path not in sys.path:
        sys.path.append(vendor_path)


def _load_faiss_module():
    _ensure_vendor_path()
    try:
        return importlib.import_module("faiss")
    except ImportError as exc:
        raise RuntimeError(
            "FAISS is not available. Install `faiss-cpu` into the repo-local "
            "`.vendor` directory before rebuilding or querying the semantic index."
        ) from exc


@dataclass(frozen=True)
class IndexedDocument:
    document_name: str
    source_path: str
    content: str


@dataclass(frozen=True)
class DocumentChunk:
    chunk_id: str
    document_name: str
    source_path: str
    chunk_index: int
    text: str


class SentenceTransformerEncoder:
    def __init__(
        self,
        model_name: str,
        *,
        batch_size: int,
        local_files_only: bool,
    ) -> None:
        self.model_name = model_name
        self.batch_size = batch_size
        self.local_files_only = local_files_only
        self._model = None
        self._lock = Lock()

    def _load_model(self):
        if self._model is not None:
            return self._model

        with self._lock:
            if self._model is None:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(
                    self.model_name,
                    local_files_only=self.local_files_only,
                )

        return self._model

    def encode(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, 0), dtype="float32")

        model = self._load_model()
        embeddings = model.encode(
            texts,
            batch_size=self.batch_size,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(embeddings, dtype="float32")


class SemanticRetriever:
    def __init__(
        self,
        *,
        docs_dir: Path,
        index_dir: Path,
        model_name: str,
        top_k: int,
        min_score: float,
        chunk_size: int,
        chunk_overlap: int,
        sentence_window_size: int,
        sentence_window_overlap: int,
        batch_size: int,
        local_files_only: bool,
        encoder: SentenceTransformerEncoder | None = None,
    ) -> None:
        self.docs_dir = docs_dir
        self.index_dir = index_dir
        self.model_name = model_name
        self.top_k = top_k
        self.min_score = min_score
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.sentence_window_size = max(1, sentence_window_size)
        self.sentence_window_overlap = max(0, sentence_window_overlap)
        self.batch_size = batch_size
        self.local_files_only = local_files_only
        self.encoder = encoder or SentenceTransformerEncoder(
            model_name=model_name,
            batch_size=batch_size,
            local_files_only=local_files_only,
        )
        self.index_path = self.index_dir / "semantic.faiss"
        self.metadata_path = self.index_dir / "chunks.json"
        self.manifest_path = self.index_dir / "manifest.json"
        self._lock = Lock()
        self._index = None
        self._chunks: list[DocumentChunk] = []
        self._manifest: dict[str, Any] | None = None

    def _iter_document_paths(self) -> list[Path]:
        if not self.docs_dir.exists():
            return []
        return sorted(path for path in self.docs_dir.rglob("*.txt") if path.is_file())

    def _relative_source_path(self, path: Path) -> str:
        base_dir = get_settings().base_dir
        try:
            return path.relative_to(base_dir).as_posix()
        except ValueError:
            return path.relative_to(self.docs_dir.parent).as_posix()

    def _docs_snapshot(self) -> list[dict[str, Any]]:
        return [
            {
                "document_name": path.name,
                "source_path": self._relative_source_path(path),
                "mtime_ns": path.stat().st_mtime_ns,
                "size": path.stat().st_size,
            }
            for path in self._iter_document_paths()
        ]

    def _build_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "model_name": self.model_name,
            "chunk_size": self.chunk_size,
            "chunk_overlap": self.chunk_overlap,
            "sentence_window_size": self.sentence_window_size,
            "sentence_window_overlap": self.sentence_window_overlap,
            "docs": self._docs_snapshot(),
        }

    def _chunk_embedding_text(self, chunk: DocumentChunk) -> str:
        title = chunk.document_name.rsplit(".", 1)[0].replace("_", " ")
        return f"{title}. {chunk.text}"

    def _split_sentences(self, text: str) -> list[str]:
        normalized_lines = "\n".join(line.strip() for line in text.splitlines())
        paragraphs = [
            " ".join(paragraph.split())
            for paragraph in PARAGRAPH_SPLIT_PATTERN.split(normalized_lines)
            if paragraph.strip()
        ]

        sentences: list[str] = []
        for paragraph in paragraphs:
            parts = [part.strip() for part in SENTENCE_SPLIT_PATTERN.split(paragraph) if part.strip()]
            sentences.extend(parts or [paragraph])
        return sentences

    def _wrap_long_sentence(self, sentence: str) -> list[str]:
        if len(sentence) <= self.chunk_size:
            return [sentence]
        return textwrap.wrap(
            sentence,
            width=self.chunk_size,
            break_long_words=False,
            break_on_hyphens=False,
        )

    def _prepare_sentences(self, content: str) -> list[str]:
        sentences = self._split_sentences(content)
        prepared: list[str] = []
        for sentence in sentences:
            prepared.extend(part for part in self._wrap_long_sentence(sentence) if part.strip())
        return prepared

    def _chunk_document(self, document: IndexedDocument) -> list[DocumentChunk]:
        sentences = self._prepare_sentences(document.content)
        if not sentences:
            return []

        chunks: list[DocumentChunk] = []
        window = self.sentence_window_size
        stride = max(1, window - self.sentence_window_overlap)

        start = 0
        while start < len(sentences):
            window_sentences = sentences[start:start + window]
            if not window_sentences:
                break

            current_sentences: list[str] = []
            for sentence in window_sentences:
                candidate = " ".join(current_sentences + [sentence]).strip()
                if current_sentences and len(candidate) > self.chunk_size:
                    break
                current_sentences.append(sentence)

            if not current_sentences:
                current_sentences = [window_sentences[0]]

            chunk_index = len(chunks)
            chunk_text = " ".join(current_sentences).strip()
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{document.source_path}:{chunk_index}",
                    document_name=document.document_name,
                    source_path=document.source_path,
                    chunk_index=chunk_index,
                    text=chunk_text,
                )
            )

            if start + window >= len(sentences):
                break
            start += stride

        if len(sentences) > 1:
            trailing_sentences = sentences[-max(1, self.chunk_overlap + 1):]
            trailing_text = " ".join(trailing_sentences).strip()
            if chunks and trailing_text != chunks[-1].text:
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"{document.source_path}:{len(chunks)}",
                        document_name=document.document_name,
                        source_path=document.source_path,
                        chunk_index=len(chunks),
                        text=trailing_text,
                    )
                )

        return chunks

    def _load_documents(self) -> list[IndexedDocument]:
        documents: list[IndexedDocument] = []
        for file_path in self._iter_document_paths():
            content = file_path.read_text(encoding="utf-8").strip()
            if content:
                documents.append(
                    IndexedDocument(
                        document_name=file_path.name,
                        source_path=self._relative_source_path(file_path),
                        content=content,
                    )
                )
        return documents

    def load_documents(self) -> list[dict[str, Any]]:
        return [asdict(document) for document in self._load_documents()]

    def _chunk_documents(self) -> list[DocumentChunk]:
        chunks: list[DocumentChunk] = []
        for document in self._load_documents():
            chunks.extend(self._chunk_document(document))
        return chunks

    def _persist_index(self, chunks: list[DocumentChunk], index) -> None:
        faiss = _load_faiss_module()
        self.index_dir.mkdir(parents=True, exist_ok=True)
        faiss.write_index(index, str(self.index_path))
        self.metadata_path.write_text(
            json.dumps([asdict(chunk) for chunk in chunks], indent=2),
            encoding="utf-8",
        )
        self.manifest_path.write_text(
            json.dumps(self._build_manifest(), indent=2),
            encoding="utf-8",
        )

    def _load_persisted_index(self) -> None:
        faiss = _load_faiss_module()
        self._index = faiss.read_index(str(self.index_path))
        self._chunks = [
            DocumentChunk(**chunk)
            for chunk in json.loads(self.metadata_path.read_text(encoding="utf-8"))
        ]
        self._manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def _index_is_current(self) -> bool:
        if not (self.index_path.exists() and self.metadata_path.exists() and self.manifest_path.exists()):
            return False

        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False

        return manifest == self._build_manifest()

    def rebuild_index(self) -> dict[str, Any]:
        faiss = _load_faiss_module()
        chunks = self._chunk_documents()
        if not chunks:
            raise RuntimeError(f"No chunkable documents found in `{self.docs_dir}`.")

        embeddings = self.encoder.encode([self._chunk_embedding_text(chunk) for chunk in chunks])
        if embeddings.size == 0:
            raise RuntimeError("No embeddings were generated for the document chunks.")

        index = faiss.IndexFlatIP(int(embeddings.shape[1]))
        index.add(embeddings)
        self._persist_index(chunks, index)
        self._index = index
        self._chunks = chunks
        self._manifest = self._build_manifest()

        return {
            "documents": len(self._load_documents()),
            "chunks": len(chunks),
            "dimensions": int(embeddings.shape[1]),
            "index_path": str(self.index_path),
        }

    def ensure_index(self) -> None:
        if self._index is not None and self._chunks:
            return

        with self._lock:
            if self._index is not None and self._chunks:
                return

            if self._index_is_current():
                self._load_persisted_index()
            else:
                self.rebuild_index()

    def retrieve(self, query: str, top_k: int | None = None) -> dict[str, Any] | None:
        normalized_query = " ".join(query.split())
        if not normalized_query:
            return None

        self.ensure_index()
        query_embedding = self.encoder.encode([normalized_query])
        if query_embedding.size == 0:
            return None

        active_top_k = max(1, top_k or self.top_k)
        distances, indices = self._index.search(query_embedding, active_top_k)

        matches: list[dict[str, Any]] = []
        seen_chunk_ids: set[str] = set()

        for score, index_id in zip(distances[0], indices[0]):
            if index_id < 0:
                continue

            chunk = self._chunks[int(index_id)]
            if chunk.chunk_id in seen_chunk_ids:
                continue

            similarity = float(score)
            if similarity < self.min_score:
                continue

            seen_chunk_ids.add(chunk.chunk_id)
            matches.append(
                {
                    "document_name": chunk.document_name,
                    "source_path": chunk.source_path,
                    "chunk_id": chunk.chunk_id,
                    "chunk_index": chunk.chunk_index,
                    "text": chunk.text,
                    "score": similarity,
                }
            )

        if not matches:
            return None

        retrieved_sources: list[str] = []
        retrieved_documents: list[str] = []
        for match in matches:
            if match["source_path"] not in retrieved_sources:
                retrieved_sources.append(match["source_path"])
            if match["document_name"] not in retrieved_documents:
                retrieved_documents.append(match["document_name"])

        combined_content = "\n\n".join(
            f"[Source: {match['source_path']} | Chunk {match['chunk_index'] + 1} | Score {match['score']:.3f}]\n"
            f"{match['text']}"
            for match in matches
        )

        return {
            "filename": ", ".join(retrieved_documents),
            "content": combined_content,
            "score": matches[0]["score"],
            "source_paths": retrieved_sources,
            "chunks": matches,
        }


DocumentRetriever = SemanticRetriever
_default_retriever: SemanticRetriever | None = None


def get_retriever() -> SemanticRetriever:
    global _default_retriever

    if _default_retriever is None:
        settings = get_settings()
        _default_retriever = SemanticRetriever(
            docs_dir=settings.docs_dir,
            index_dir=settings.retrieval_index_dir,
            model_name=settings.semantic_model_name,
            top_k=settings.retrieval_top_k,
            min_score=settings.retrieval_min_score,
            chunk_size=settings.retrieval_chunk_size,
            chunk_overlap=settings.retrieval_chunk_overlap,
            sentence_window_size=settings.retrieval_chunk_sentence_window,
            sentence_window_overlap=settings.retrieval_chunk_sentence_overlap,
            batch_size=settings.retrieval_batch_size,
            local_files_only=settings.semantic_local_files_only,
        )

    return _default_retriever


def reset_retriever() -> None:
    global _default_retriever
    _default_retriever = None


def load_documents(retriever: SemanticRetriever | None = None) -> list[dict[str, Any]]:
    active_retriever = retriever or get_retriever()
    return active_retriever.load_documents()


def rebuild_index(retriever: SemanticRetriever | None = None) -> dict[str, Any]:
    active_retriever = retriever or get_retriever()
    return active_retriever.rebuild_index()


def retrieve_document(
    query: str,
    retriever: SemanticRetriever | None = None,
    top_k: int | None = None,
) -> dict[str, Any] | None:
    active_retriever = retriever or get_retriever()
    return active_retriever.retrieve(query, top_k=top_k)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Semantic retrieval index management.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("rebuild-index", help="Rebuild the semantic FAISS index.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    if args.command == "rebuild-index":
        result = rebuild_index()
        print(json.dumps(result, indent=2))
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
