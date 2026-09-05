"""Embedded-URL extraction from free-form pasted text (TEXT/EMAIL bodies).

Scam SMS/chat messages very often include a link with no "http(s)://"
prefix at all (e.g. "kredt.be/3u9CoOh", frequently wrapped in brackets),
since that's shorter and still clickable in most messaging apps. Without
extracting these, a pasted message's embedded link is invisible to the
URL analyzer entirely -- only the text-pattern rules would ever see it,
and none of those look at links.

This is intentionally conservative: it requires a plausible
domain.tld pattern (letters/digits/hyphens, a real-looking 2+ letter
TLD, then either a path/query or end-of-token) so we don't misparse
ordinary sentences containing a period. It shares no code with
app.integrations.gmail's MIME-specific `_canonical_urls` (which operates
on already-decoded base64 MIME parts, not raw pasted text), but produces
the same bounded, deduplicated, scheme-normalized output shape.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

MAX_EXTRACTED_URLS = 5

_SCHEME_URL_PATTERN = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)

# Bare "domain.tld/path" or "domain.tld" with no scheme. Requires a
# realistic TLD length (2-24 letters) to avoid matching decimals or
# versioned text (e.g. "3.25", "v1.2"); requires the domain label
# immediately before the dot to start with a letter so "3u9CoOh" itself
# is never mistaken for a domain, and requires at least one dot.
_BARE_DOMAIN_PATTERN = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9-]{0,61}(?:\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,24}"
    r"(?:/[^\s<>\"'\]\)]*)?",
)

# Common non-URL matches to reject even though they fit the bare-domain
# shape (versioned identifiers, decimals already excluded by requiring a
# letter TLD, but e.g. "e.g." or "etc." style abbreviations are not real
# links either).
_BARE_DOMAIN_TLD_BLOCKLIST = {"e", "g", "etc", "vs", "eg"}


def _clean_candidate(candidate: str, *, had_scheme: bool) -> tuple[str, str] | None:
    """Returns (dedup_key, normalized_url), or None if not a plausible URL.

    dedup_key ignores scheme (host+path+query) so a bare-domain match for
    a link already found with an explicit scheme is recognized as the
    same URL rather than a false duplicate with a guessed scheme.
    """
    cleaned = candidate.rstrip(".,;:!?)]}\"'")
    parseable = cleaned if had_scheme else f"http://{cleaned}"
    parsed = urlsplit(parseable)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    host = parsed.netloc.lower()
    if "." not in host:
        return None
    tld = host.rsplit(".", maxsplit=1)[-1]
    if tld in _BARE_DOMAIN_TLD_BLOCKLIST:
        return None
    scheme = parsed.scheme.lower() if had_scheme else "http"
    path = parsed.path or "/"
    dedup_key = urlunsplit(("", host, path, parsed.query, ""))
    return dedup_key, urlunsplit((scheme, host, path, parsed.query, ""))


def extract_urls_from_text(text: str) -> tuple[int, tuple[str, ...]]:
    """Extract, normalize, and deduplicate embedded links from plain text.

    Returns (total_found_before_limit, bounded_unique_urls) -- mirrors
    app.integrations.gmail._canonical_urls's return shape so callers can
    treat both sources identically for analysis_coverage reporting.
    Links already found with an explicit scheme take priority over a
    bare-domain rematch of the same host+path.
    """
    seen: dict[str, str] = {}
    for candidate in _SCHEME_URL_PATTERN.findall(text):
        result = _clean_candidate(candidate, had_scheme=True)
        if result:
            key, normalized = result
            seen.setdefault(key, normalized)
    for candidate in _BARE_DOMAIN_PATTERN.findall(text):
        result = _clean_candidate(candidate, had_scheme=False)
        if result:
            key, normalized = result
            seen.setdefault(key, normalized)
    unique = list(seen.values())
    return len(unique), tuple(unique[:MAX_EXTRACTED_URLS])
