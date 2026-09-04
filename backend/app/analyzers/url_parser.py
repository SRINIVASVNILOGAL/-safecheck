"""URL parsing and PSL-based decomposition.

Uses tldextract for Public Suffix List (PSL)-aware domain decomposition,
so "sbi.co.in" is correctly split into SLD="sbi", suffix="co.in" rather
than naively splitting on the last dot (which would incorrectly treat
"co.in" itself as the "domain"). This module contains no fraud-detection
logic -- it only parses. Detection logic lives in url_rules.py (Step 2+).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import tldextract


@dataclass(frozen=True)
class ParsedUrl:
    """Structural decomposition of a URL. No fraud judgement here."""

    raw_url: str
    scheme: str
    full_host: str
    sld: str  # second-level domain, e.g. "sbi" in sbi.co.in
    suffix: str  # public suffix, e.g. "co.in"
    registered_domain: str  # e.g. "sbi.co.in"
    subdomain: str  # e.g. "www" in www.sbi.co.in
    path: str
    is_ip_hostname: bool
    has_userinfo: bool  # deceptive "@" in the URL, e.g. http://real.com@evil.com


def parse_url(raw_url: str) -> ParsedUrl:
    """Parse a URL string into its structural components.

    Does not raise on malformed input -- returns a ParsedUrl with empty
    fields where parsing fails, so callers (url_rules.py) can decide how
    to score "this doesn't even look like a URL" as its own evidence
    signal rather than the parser crashing.
    """
    parsed = urlparse(raw_url.strip())

    netloc = parsed.netloc
    has_userinfo = "@" in netloc
    # Strip userinfo (user:pass@) before extracting the host, since
    # tldextract/urlparse's .hostname already does this, but we want to
    # detect the deceptive pattern first.
    host = parsed.hostname or ""

    extracted = tldextract.extract(raw_url.strip())

    is_ip_hostname = _looks_like_ip(host)

    return ParsedUrl(
        raw_url=raw_url,
        scheme=parsed.scheme.lower(),
        full_host=host.lower(),
        sld=extracted.domain.lower(),
        suffix=extracted.suffix.lower(),
        registered_domain=extracted.top_domain_under_public_suffix.lower(),
        subdomain=extracted.subdomain.lower(),
        path=parsed.path,
        is_ip_hostname=is_ip_hostname,
        has_userinfo=has_userinfo,
    )


def _looks_like_ip(host: str) -> bool:
    """True if `host` is a bare IPv4 address rather than a domain name.

    Deliberately simple (no IPv6 handling yet -- not a common phishing
    vector for this use case, and can be added later if real cases show
    it's needed).
    """
    if not host:
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
