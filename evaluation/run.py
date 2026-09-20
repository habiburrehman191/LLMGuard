from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluation.dataset import DEFAULT_DATASET_PATH
from evaluation.harness import DEFAULT_OUTPUT_DIR, MODE_ORDER, run_benchmark


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the synthetic LLMGuard Phase 14B security benchmark.",
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=MODE_ORDER,
        default=list(MODE_ORDER),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Repeated deterministic runs (1-100; default: 3).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_benchmark(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        modes=args.modes,
        seed=args.seed,
        run_count=args.runs,
    )
    summary = {
        "dataset_case_count": payload["metadata"]["dataset_case_count"],
        "modes": args.modes,
        "run_count": args.runs,
        "metrics": payload["metrics"],
        "output_files": payload["output_files"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
