"""Shared pytest fixtures.

anyio_backend selects asyncio as the backend for tests marked
@pytest.mark.anyio (used by test_google_safe_browsing.py and future
async integration adapters, e.g. VirusTotal in Step 5).
"""

from __future__ import annotations

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
