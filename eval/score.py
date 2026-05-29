# ruff: noqa: T201, RUF002
"""Скоринг детектора red flags на размеченном train.json.

Считает micro и покатегорийные precision/recall/F1 и печатает разбивку FP/FN по сессиям —
это позволяет подбирать пороги (app/prompts.py: CATEGORY_THRESHOLDS) и оценивать эффект
self-consistency / verifier на реальных данных, а не вслепую.

Запуск (нужен ключ для живых вызовов LLM):
    OPENROUTER_API_KEY=sk-or-... \
    DETECTION_RUNS=3 DETECTION_TEMPERATURE=0.4 VERIFIER_ENABLED=1 \
    .venv/bin/python -m eval.score

Метрики тут считаются по МНОЖЕСТВУ категорий на сессию — так же, как evaluator сравнивает
predicted_red_flags с expected_red_flags (см. app/routers/check.py).
"""

from __future__ import annotations

import collections
import json
import pathlib
import sys

from app.models import load_llm, process_risk_detection
from app.prompts import CATEGORY_THRESHOLDS

_TRAIN_PATH = pathlib.Path(__file__).parent.parent / "train.json"
_ALL_CATEGORIES = sorted(CATEGORY_THRESHOLDS)


def _format_dialogue(messages: list[dict[str, str]]) -> str:
    return "\n".join(f"{m['role']}: {m['content']}" for m in messages)


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def main() -> int:
    sessions = json.loads(_TRAIN_PATH.read_text(encoding="utf-8"))
    llm_client = load_llm()
    if not llm_client.api_key:
        print("ERROR: OPENROUTER_API_KEY не задан — живые вызовы невозможны.", file=sys.stderr)
        return 1

    tp = collections.Counter[str]()
    fp = collections.Counter[str]()
    fn = collections.Counter[str]()
    fp_sessions: list[tuple[str, str]] = []
    fn_sessions: list[tuple[str, str]] = []

    for index, session in enumerate(sessions):
        expected = {f["category"] for f in session["expected_red_flags"]}
        dialogue = _format_dialogue(session["messages"])
        predicted = {f["category"] for f in process_risk_detection(llm_client, dialogue)}

        for category in predicted - expected:
            fp[category] += 1
            fp_sessions.append((category, session["session_id"]))
        for category in expected - predicted:
            fn[category] += 1
            fn_sessions.append((category, session["session_id"]))
        for category in predicted & expected:
            tp[category] += 1

        print(f"[{index:2d}] exp={sorted(expected)} pred={sorted(predicted)}")

    print("\n==== PER-CATEGORY (порог в скобках) ====")
    for category in _ALL_CATEGORIES:
        precision, recall, f1 = _prf(tp[category], fp[category], fn[category])
        print(
            f"  {category:24s} (thr {CATEGORY_THRESHOLDS[category]:.2f})  "
            f"P={precision:.2f} R={recall:.2f} F1={f1:.2f}  "
            f"TP={tp[category]} FP={fp[category]} FN={fn[category]}"
        )

    total_tp, total_fp, total_fn = sum(tp.values()), sum(fp.values()), sum(fn.values())
    micro_p, micro_r, micro_f1 = _prf(total_tp, total_fp, total_fn)
    print("\n==== MICRO ====")
    print(f"  P={micro_p:.3f}  R={micro_r:.3f}  F1={micro_f1:.3f}  (TP={total_tp} FP={total_fp} FN={total_fn})")

    print("\n==== FALSE POSITIVES (срезать порогом/verifier) ====")
    for category, session_id in fp_sessions:
        print(f"  +{category}  {session_id}")
    print("\n==== FALSE NEGATIVES (пропуски — recall) ====")
    for category, session_id in fn_sessions:
        print(f"  -{category}  {session_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
