"""Loads the shared fraud-detection config (shared/fraud-config.json).

Per docs/scoring-engine.md Section 5, this config is meant to be identical
across the web backend and the Android app. Load it once at import time
and expose it as simple, typed accessors so the rest of the URL analyzer
doesn't need to know about the JSON file's shape.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

# shared/ lives at the repo root, three levels up from this file:
# backend/app/analyzers/url_config.py -> backend/app/analyzers -> backend/app
# -> backend -> <repo root>/shared/fraud-config.json
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "shared" / "fraud-config.json"


@lru_cache(maxsize=1)
def _load_raw_config() -> dict:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Shared fraud config not found at {_CONFIG_PATH}. "
            "This file must exist at <repo root>/shared/fraud-config.json."
        )
    with _CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_brand_domain_map() -> dict[str, list[str]]:
    return _load_raw_config()["brand_domain_map"]


def get_high_risk_tlds() -> frozenset[str]:
    return frozenset(_load_raw_config()["high_risk_tlds"])


def get_url_shorteners() -> frozenset[str]:
    return frozenset(_load_raw_config()["url_shorteners"])


def get_levenshtein_max_distance() -> int:
    return _load_raw_config()["levenshtein_max_distance"]


def get_levenshtein_length_window() -> tuple[int, int]:
    low, high = _load_raw_config()["levenshtein_length_window"]
    return (low, high)
