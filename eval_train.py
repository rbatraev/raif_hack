# ruff: noqa: C901, PLR0912, PLR0915, T201
"""Evaluate the red flag detector on train.json and print metrics."""

from __future__ import annotations

import json
import time
import typing
from collections import Counter
from pathlib import Path

from app.models import LLMClient, process_risk_detection
from app.routers.check import DialogueMessage, format_dialogue

EvalResult = dict[str, typing.Any]


def format_flag_debug(one_flag: dict[str, typing.Any]) -> str:
    category = str(one_flag.get("category", "unknown"))
    correct_probability = float(one_flag.get("correct_probability", one_flag.get("confidence", 0.0)))
    obvious_marker = "obvious" if bool(one_flag.get("is_obvious", False)) else "check"
    return f"{category}:{correct_probability:.2f}:{obvious_marker}"


def main() -> None:
    with Path("train.json").open(encoding="utf-8") as f:
        data = json.load(f)

    client = LLMClient()
    if not client.api_key:
        print("WARNING: OPENROUTER_API_KEY not set; hardcoded hits will be evaluated, LLM misses return empty flags")

    results: list[EvalResult] = []
    total_time = 0.0

    for i, session in enumerate(data):
        session_id = session["session_id"]
        messages = [DialogueMessage(**m) for m in session["messages"]]
        expected = {flag["category"] for flag in session.get("expected_red_flags", [])}

        raw_text = format_dialogue(messages)

        t0 = time.perf_counter()
        detected_flags, source = process_risk_detection(client, raw_text)
        elapsed = time.perf_counter() - t0
        total_time += elapsed

        predicted = {f["category"] for f in detected_flags}
        predicted_debug = [format_flag_debug(one_flag) for one_flag in detected_flags]

        tp = expected & predicted
        fp = predicted - expected
        fn = expected - predicted

        status = "OK" if not fp and not fn else "MISS" if fn else "EXTRA" if fp else "MIXED"
        if fp and fn:
            status = "MIXED"

        results.append(
            {
                "session_id": session_id,
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "predicted_debug": predicted_debug,
                "tp": sorted(tp),
                "fp": sorted(fp),
                "fn": sorted(fn),
                "status": status,
                "time_ms": int(elapsed * 1000),
                "raw_flags": detected_flags,
                "source": source,
            }
        )

        icon = "OK" if status == "OK" else "ERR"
        print(
            f"[{i + 1:2d}/{len(data)}] {icon} {session_id}  expected={sorted(expected)}  "
            f"predicted={predicted_debug}  {f'FP={sorted(fp)}' if fp else ''}  "
            f"{f'FN={sorted(fn)}' if fn else ''}  source={source}  ({int(elapsed * 1000)}ms)"
        )

    # === METRICS ===
    print("\n" + "=" * 80)
    print("METRICS")
    print("=" * 80)

    all_tp = sum(len(r["tp"]) for r in results)
    all_fp = sum(len(r["fp"]) for r in results)
    all_fn = sum(len(r["fn"]) for r in results)

    precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0
    recall = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    exact_match = sum(1 for r in results if not r["fp"] and not r["fn"]) / len(results)
    clean_dialogues = [r for r in results if not r["expected"]]
    flagged_dialogues = [r for r in results if r["expected"]]
    clean_false_positive_rate = (
        sum(1 for r in clean_dialogues if r["predicted"]) / len(clean_dialogues) if clean_dialogues else 0
    )
    flagged_miss_rate = (
        sum(1 for r in flagged_dialogues if r["fn"]) / len(flagged_dialogues) if flagged_dialogues else 0
    )

    print(f"TP: {all_tp}  FP: {all_fp}  FN: {all_fn}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")
    print(f"Exact match accuracy: {exact_match:.3f}")
    print(f"Clean false positive rate: {clean_false_positive_rate:.3f}")
    print(f"Flagged miss rate: {flagged_miss_rate:.3f}")
    print(f"Total time: {total_time:.1f}s  Avg: {total_time / len(data):.1f}s")
    print(f"Hardcoded hits: {sum(1 for r in results if r['source'] == 'hardcoded')}")
    print(f"LLM path empty/no-flag results: {sum(1 for r in results if r['source'] == 'llm')}")

    # Per-category breakdown
    categories = set()
    for r in results:
        categories.update(r["expected"])
        categories.update(r["predicted"])

    print("\nPer-category breakdown:")
    for cat in sorted(categories):
        cat_tp = sum(1 for r in results if cat in r["tp"])
        cat_fp = sum(1 for r in results if cat in r["fp"])
        cat_fn = sum(1 for r in results if cat in r["fn"])
        cat_p = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
        cat_r = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
        cat_f1 = 2 * cat_p * cat_r / (cat_p + cat_r) if (cat_p + cat_r) > 0 else 0
        print(f"  {cat:25s}  TP={cat_tp} FP={cat_fp} FN={cat_fn}  P={cat_p:.2f} R={cat_r:.2f} F1={cat_f1:.2f}")

    confusion = Counter(
        (expected_cat, predicted_cat) for r in results for expected_cat in r["fn"] for predicted_cat in r["fp"]
    )
    if confusion:
        print("\nLikely category confusions:")
        for (expected_cat, predicted_cat), count in confusion.most_common():
            print(f"  expected={expected_cat:25s} predicted={predicted_cat:25s} count={count}")

    clean_errors = [r for r in results if not r["expected"] and r["predicted"]]
    if clean_errors:
        print(f"\n{len(clean_errors)} clean-dialogue false positives:")
        for r in clean_errors:
            print(f"  {r['session_id']}  predicted={r['predicted_debug']}")

    missed_flagged = [r for r in results if r["expected"] and r["fn"]]
    if missed_flagged:
        print(f"\n{len(missed_flagged)} flagged-dialogue misses:")
        for r in missed_flagged:
            print(f"  {r['session_id']}  expected={r['expected']}  predicted={r['predicted_debug']}  FN={r['fn']}")

    # Show errors
    errors = [r for r in results if r["status"] != "OK"]
    if errors:
        print(f"\n{len(errors)} errors:")
        for r in errors:
            print(
                f"  {r['session_id']}  expected={r['expected']}  "
                f"predicted={r['predicted_debug']}  FP={r['fp']}  FN={r['fn']}"
            )


if __name__ == "__main__":
    main()
