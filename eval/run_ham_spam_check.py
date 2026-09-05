"""Offline false-positive check for SafeCheck's deterministic rule engine.

Not part of the application. Not collected by pytest. Not imported by
anything under app/. See eval/README.md for why this dataset is used this
way (ham-only false-positive check) and not as training/scoring data.

Usage:
    python eval/run_ham_spam_check.py [path/to/spam.csv]

Expects the UCI/Kaggle "SMS Spam Collection" CSV format:
    v1,v2
    ham,"Go until jurong point, crazy.. Available only in bugis n great world la e buffet..."
    spam,"Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005..."

Only the first two columns (label, text) are used; any trailing empty
columns from the original export are ignored.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.risk.engine import calculate_risk  # noqa: E402
from app.risk.rules import run_all_rules  # noqa: E402


def load_rows(csv_path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with csv_path.open("r", encoding="latin-1", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) < 2:
                continue
            label, text = row[0].strip().lower(), row[1]
            if label in {"ham", "spam"} and text.strip():
                rows.append((label, text))
    return rows


def main() -> None:
    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "data" / "spam.csv"
    if not csv_path.exists():
        print(f"CSV not found at {csv_path}.")
        print("Place the UCI/Kaggle SMS Spam Collection CSV there, or pass a path as an argument.")
        sys.exit(1)

    rows = load_rows(csv_path)
    ham_rows = [text for label, text in rows if label == "ham"]
    spam_rows = [text for label, text in rows if label == "spam"]
    print(f"Loaded {len(rows)} rows ({len(ham_rows)} ham, {len(spam_rows)} spam) from {csv_path}")

    # --- False-positive check on ham messages ---
    # A "false positive" here means a genuinely benign message scored
    # UNCERTAIN or above by the local text rules alone (no URL/network
    # calls -- this script never makes network requests).
    ham_bands = Counter()
    ham_false_positives: list[tuple[str, int, list[str]]] = []
    for text in ham_rows:
        evidence = run_all_rules(text)
        result = calculate_risk(evidence)
        ham_bands[result.band] += 1
        if result.band != "LOW":
            ham_false_positives.append((text, result.score, [e.signal for e in evidence]))

    print("\n--- Ham message band distribution (expect ~all LOW) ---")
    for band in ("LOW", "UNCERTAIN", "MEDIUM", "HIGH"):
        print(f"  {band}: {ham_bands.get(band, 0)}")

    fp_rate = len(ham_false_positives) / len(ham_rows) * 100 if ham_rows else 0
    print(f"\nFalse-positive rate on ham: {len(ham_false_positives)}/{len(ham_rows)} ({fp_rate:.2f}%)")
    if ham_false_positives:
        print("\nSample false positives (up to 15):")
        for text, score, signals in ham_false_positives[:15]:
            print(f"  [{score}] {signals} :: {text[:100]!r}")

    # --- Spam recall (context only -- most of this spam is premium-rate
    # ringtone/chatline spam, not SafeCheck's target fraud categories, so
    # this number is informational, not a pass/fail product metric). ---
    spam_flagged = 0
    for text in spam_rows:
        evidence = run_all_rules(text)
        result = calculate_risk(evidence)
        if result.band != "LOW":
            spam_flagged += 1
    recall = spam_flagged / len(spam_rows) * 100 if spam_rows else 0
    print(f"\n(Informational only) Spam messages flagged above LOW: {spam_flagged}/{len(spam_rows)} ({recall:.2f}%)")
    print("Low recall here is expected and not a bug -- most of this spam is")
    print("premium-rate ringtone/chatline spam, not SafeCheck's target fraud types.")


if __name__ == "__main__":
    main()
