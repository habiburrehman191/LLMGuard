from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from app.benchmark_presentation import FINAL_REPORT, load_benchmark_presentation
from evaluation.artifact_hashing import (
    binary_sha256,
    canonical_text_sha256,
    canonical_text_sha256_bytes,
    canonicalize_utf8_text,
)
from evaluation.dataset import DEFAULT_DATASET_PATH, load_evaluation_cases
from evaluation.harness import _detector_source_hashes, _metadata


class EvaluationArtifactIntegrityTests(unittest.TestCase):
    def test_lf_crlf_and_lone_cr_have_one_canonical_text_hash(self) -> None:
        lf = b'first\nsecond\nthird\n'
        crlf = b'first\r\nsecond\r\nthird\r\n'
        lone_cr = b'first\rsecond\rthird\r'
        expected = hashlib.sha256(lf).hexdigest()

        self.assertEqual(lf, canonicalize_utf8_text(crlf))
        self.assertEqual(expected, canonical_text_sha256_bytes(lf))
        self.assertEqual(expected, canonical_text_sha256_bytes(crlf))
        self.assertEqual(expected, canonical_text_sha256_bytes(lone_cr))

    def test_actual_text_content_change_changes_canonical_hash(self) -> None:
        original = b'{"case_id":"synthetic-1","label":"benign"}\r\n'
        changed = b'{"case_id":"synthetic-1","label":"malicious"}\n'
        self.assertNotEqual(
            canonical_text_sha256_bytes(original),
            canonical_text_sha256_bytes(changed),
        )

    def test_current_dataset_matches_stored_final_benchmark_hash(self) -> None:
        report = json.loads(FINAL_REPORT.read_text(encoding='utf-8'))
        self.assertEqual(
            report['metadata']['dataset_sha256'],
            canonical_text_sha256(DEFAULT_DATASET_PATH),
        )
        self.assertEqual(
            'ec3cb54648f2f94909c5dd1dc7c27ce0df1588deadbcacdf769a049777bf11e8',
            canonical_text_sha256(DEFAULT_DATASET_PATH),
        )

    def test_binary_hashing_remains_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'artifact.joblib'
            payload = b'\x80\x04binary\r\nbytes\x00\xff\rpayload'
            binary.write_bytes(payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), binary_sha256(binary))

            changed_line_endings = payload.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
            self.assertNotEqual(
                binary_sha256(binary),
                hashlib.sha256(changed_line_endings).hexdigest(),
            )

    def test_detector_source_hashes_are_stable_across_lf_and_crlf(self) -> None:
        relative_paths = (
            'app/firewall.py',
            'app/semantic_firewall.py',
            'app/ml_firewall.py',
            'app/hybrid_firewall.py',
            'app/input_guard.py',
            'app/context_guard.py',
            'app/output_guard.py',
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path in relative_paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'def inspect():\n    return "synthetic"\n')
            lf_hashes = _detector_source_hashes(root)
            for relative_path in relative_paths:
                path = root / relative_path
                path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
            self.assertEqual(lf_hashes, _detector_source_hashes(root))

    def test_text_configuration_hash_is_stable_across_lf_and_crlf(self) -> None:
        lf = b'{\n  "block_risk_threshold": 0.92,\n  "semantic_threshold": 0.45\n}\n'
        crlf = lf.replace(b'\n', b'\r\n')
        self.assertEqual(
            canonical_text_sha256_bytes(lf),
            canonical_text_sha256_bytes(crlf),
        )

    def test_report_generation_metadata_uses_canonical_dataset_hash(self) -> None:
        source = DEFAULT_DATASET_PATH.read_bytes()
        crlf = source.replace(b'\r\n', b'\n').replace(b'\r', b'\n').replace(b'\n', b'\r\n')
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / 'security_cases.jsonl'
            dataset.write_bytes(crlf)
            cases = load_evaluation_cases(dataset)
            order_hash = canonical_text_sha256_bytes(
                '\n'.join(case.case_id for case in cases).encode('utf-8')
            )
            metadata = _metadata(
                dataset_path=dataset,
                cases=cases,
                seed=42,
                run_count=1,
                run_seeds=[42],
                case_order_sha256=order_hash,
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(canonical_text_sha256(DEFAULT_DATASET_PATH), metadata['dataset_sha256'])

    def test_frontend_accepts_crlf_checkout_of_existing_dataset(self) -> None:
        source = DEFAULT_DATASET_PATH.read_bytes()
        crlf = source.replace(b'\r\n', b'\n').replace(b'\r', b'\n').replace(b'\n', b'\r\n')
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / 'security_cases.jsonl'
            dataset.write_bytes(crlf)
            presentation = load_benchmark_presentation(dataset)
        self.assertTrue(presentation['available'], presentation)
        self.assertEqual(54, presentation['case_count'])

    def test_frontend_rejects_logically_changed_dataset(self) -> None:
        source = DEFAULT_DATASET_PATH.read_bytes()
        changed = source.replace(
            b'published admission office hours',
            b'published admissions office hours',
            1,
        )
        self.assertNotEqual(source, changed)
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / 'security_cases.jsonl'
            dataset.write_bytes(changed)
            presentation = load_benchmark_presentation(dataset)
        self.assertFalse(presentation['available'])
        self.assertEqual(
            'The stored final report does not match the current dataset.',
            presentation['reason'],
        )

    def test_invalid_utf8_is_not_silently_reinterpreted(self) -> None:
        with self.assertRaises(UnicodeDecodeError):
            canonical_text_sha256_bytes(b'valid\ninvalid:\xff\n')


if __name__ == '__main__':
    unittest.main()
