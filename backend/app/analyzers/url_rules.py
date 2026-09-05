"""Local, deterministic URL fraud-detection rules.

Each rule takes a ParsedUrl (see url_parser.py) and returns zero-or-one
Evidence items with category="url". These rules never make network calls
-- they only use the parsed URL structure and the shared config
(brand_domain_map, high_risk_tlds). External provider checks (Google Safe
Browsing, VirusTotal) live in separate modules (Step 4-5) since they
involve network I/O and availability handling.

Priority order for lookalike/typosquatting detection (docs/scoring-engine.md
Section 5.2, adapted from the reference architecture):
1. Whitelist: matches a brand's official domain or valid subdomain -> clean.
2. Deceptive separator: brand name with a hyphen pattern in the SLD itself.
3. Deceptive subdomain: brand name as a subdomain of an unrelated host.
4. Typosquatting: Levenshtein distance <= max_distance, within a length
   window, so we don't flag coincidentally-similar unrelated words.

These four checks are mutually exclusive per brand: as soon as one brand
match is found, we stop checking that brand (whitelisted takes priority
over flagging). A domain can still be flagged against a different brand
if somehow relevant, but in practice one URL rarely impersonates two
brands at once.
"""

from __future__ import annotations

import re

import Levenshtein

from app.analyzers.url_config import (
    get_brand_domain_map,
    get_high_risk_tlds,
    get_levenshtein_length_window,
    get_levenshtein_max_distance,
    get_url_shorteners,
)
from app.analyzers.url_parser import ParsedUrl
from app.risk.evidence import Evidence

LOOKALIKE_POINTS = 25
TYPOSQUATTING_POINTS = 25
INSECURE_HTTP_POINTS = 10
IP_HOSTNAME_POINTS = 15
HIGH_RISK_TLD_POINTS = 10
SHORTENED_LINK_POINTS = 15

# A shortener/redirect-style path is a single segment of short, dense
# alphanumeric characters with no words or extra slashes -- e.g. "/3u9CoOh"
# (bit.ly/tinyurl style) rather than a normal page path like "/personal-banking".
_SHORT_CODE_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9]{4,12}/?$")


def _is_official_or_subdomain_of(registered_domain: str, official_domains: list[str]) -> bool:
    return any(
        registered_domain == official or registered_domain.endswith(f".{official}")
        for official in official_domains
    )


def _has_deceptive_separator(sld: str, brand: str) -> bool:
    return (
        sld.startswith(f"{brand}-")
        or f"-{brand}-" in sld
        or sld.endswith(f"-{brand}")
    )


def _has_deceptive_subdomain(full_host: str, registered_domain: str, brand: str, official_domains: list[str]) -> bool:
    """Brand name appears as a subdomain label of an unrelated host.

    E.g. "sbi.malicious-site.com" -- the brand "sbi" appears in the host,
    but the actual registered domain (malicious-site.com) is not any of
    the brand's official domains.
    """
    if _is_official_or_subdomain_of(registered_domain, official_domains):
        return False
    # Match "sbi." as a labeled segment, not a substring of another word
    # (so "sbis-secure.com" doesn't false-positive via naive substring
    # matching -- we require a dot boundary after the brand name).
    return f"{brand}." in full_host


def detect_lookalike_domain(parsed: ParsedUrl) -> Evidence | None:
    """Checks 1-3: whitelist, deceptive separator, deceptive subdomain."""
    brand_map = get_brand_domain_map()

    for brand, official_domains in brand_map.items():
        if _is_official_or_subdomain_of(parsed.registered_domain, official_domains):
            # Whitelisted for this brand -- but keep checking other
            # brands in case the same domain coincidentally matches
            # another brand's pattern (rare, but the whitelist should
            # only clear the brand it actually belongs to).
            continue

        if _has_deceptive_separator(parsed.sld, brand):
            return Evidence(
                category="url",
                signal="LOOKALIKE_DOMAIN",
                points=LOOKALIKE_POINTS,
                reason=(
                    f"The domain resembles '{brand}' but uses a deceptive "
                    f"separator and does not match the official domain."
                ),
                observed_value=parsed.registered_domain,
                source="url_analyzer",
                correlation_group="CORR_LOOKALIKE",
                severity="HIGH",
            )

        if _has_deceptive_subdomain(
            parsed.full_host, parsed.registered_domain, brand, official_domains
        ):
            return Evidence(
                category="url",
                signal="LOOKALIKE_DOMAIN",
                points=LOOKALIKE_POINTS,
                reason=(
                    f"The domain uses '{brand}' as a subdomain of an "
                    f"unrelated host, not the official domain."
                ),
                observed_value=parsed.full_host,
                source="url_analyzer",
                correlation_group="CORR_LOOKALIKE",
                severity="HIGH",
            )

    return None


def detect_typosquatting(parsed: ParsedUrl) -> Evidence | None:
    """Check 4: Levenshtein distance-based typosquatting detection.

    Only runs if detect_lookalike_domain() found nothing -- these two
    checks are complementary layers, not meant to double-count the same
    domain (a domain that already triggered LOOKALIKE_DOMAIN doesn't
    also need TYPOSQUATTING evidence for the same underlying deception).
    """
    brand_map = get_brand_domain_map()
    max_distance = get_levenshtein_max_distance()
    length_low, length_high = get_levenshtein_length_window()

    for brand, official_domains in brand_map.items():
        if _is_official_or_subdomain_of(parsed.registered_domain, official_domains):
            continue

        length_diff = len(parsed.sld) - len(brand)
        if not (length_low <= length_diff <= length_high):
            continue

        distance = Levenshtein.distance(parsed.sld, brand)
        if 0 < distance <= max_distance:
            return Evidence(
                category="url",
                signal="TYPOSQUATTING",
                points=TYPOSQUATTING_POINTS,
                reason=(
                    f"The domain '{parsed.sld}' is a close spelling match "
                    f"for the brand '{brand}' (edit distance {distance})."
                ),
                observed_value=parsed.registered_domain,
                source="url_analyzer",
                correlation_group="CORR_LOOKALIKE",
                confidence=0.8,
                severity="HIGH",
            )

    return None


def detect_insecure_http(parsed: ParsedUrl) -> Evidence | None:
    """Plain HTTP (not HTTPS) is a weak, corroborating signal on its own."""
    if parsed.scheme != "http":
        return None
    return Evidence(
        category="url",
        signal="INSECURE_HTTP",
        points=INSECURE_HTTP_POINTS,
        reason="The URL uses unencrypted HTTP instead of HTTPS.",
        observed_value=parsed.scheme,
        source="url_analyzer",
        correlation_group="CORR_TRANSPORT",
        confidence=0.6,
        severity="LOW",
    )


def detect_ip_hostname(parsed: ParsedUrl) -> Evidence | None:
    """A bare IP address as a hostname is unusual for legitimate sites."""
    if not parsed.is_ip_hostname:
        return None
    return Evidence(
        category="url",
        signal="IP_HOSTNAME",
        points=IP_HOSTNAME_POINTS,
        reason="The URL uses a raw IP address instead of a domain name.",
        observed_value=parsed.full_host,
        source="url_analyzer",
        correlation_group="CORR_STRUCTURE",
        confidence=0.7,
        severity="MEDIUM",
    )


def detect_high_risk_tld(parsed: ParsedUrl) -> Evidence | None:
    """A high-risk TLD alone is a weak signal -- many legitimate sites use them."""
    if not parsed.suffix:
        return None
    # suffix can be multi-label (e.g. "co.in"); only the final label is
    # the actual TLD we check against the high-risk list.
    tld = parsed.suffix.rsplit(".", maxsplit=1)[-1]
    if tld not in get_high_risk_tlds():
        return None
    return Evidence(
        category="url",
        signal="HIGH_RISK_TLD",
        points=HIGH_RISK_TLD_POINTS,
        reason=f"The domain uses a top-level domain ('.{tld}') commonly associated with abuse.",
        observed_value=f".{tld}",
        source="url_analyzer",
        correlation_group="CORR_STRUCTURE",
        confidence=0.5,
        severity="LOW",
    )


def detect_shortened_link(parsed: ParsedUrl) -> Evidence | None:
    """Flags known URL shorteners and shortener-shaped redirect links.

    A shortened link hides the real destination, which is exactly the
    obfuscation technique used in toll/fee/delivery scam messages (e.g.
    "kredt.be/3u9CoOh"). Two cases are flagged:
    1. The domain is a known shortener service (get_url_shorteners()) --
       previously loaded from config but never actually used by any rule.
    2. The domain is unrecognized but the path looks like a shortener's
       redirect code (short, dense alphanumeric segment, no real words),
       which is how most unfamiliar shortener-style domains present.
    """
    if not parsed.registered_domain:
        return None
    if parsed.registered_domain in get_url_shorteners():
        return Evidence(
            category="url",
            signal="SHORTENED_LINK",
            points=SHORTENED_LINK_POINTS,
            reason="The URL uses a known link-shortening service, which hides the real destination.",
            observed_value=parsed.registered_domain,
            source="url_analyzer",
            correlation_group="CORR_STRUCTURE",
            confidence=0.7,
            severity="MEDIUM",
        )
    if _SHORT_CODE_PATH_PATTERN.match(parsed.path) and parsed.sld and len(parsed.sld) <= 8:
        return Evidence(
            category="url",
            signal="SHORTENED_LINK",
            points=SHORTENED_LINK_POINTS,
            reason="The URL's short domain and redirect-style path resemble a link shortener, which hides the real destination.",
            observed_value=f"{parsed.registered_domain}{parsed.path}",
            source="url_analyzer",
            correlation_group="CORR_STRUCTURE",
            confidence=0.5,
            severity="MEDIUM",
        )
    return None


def run_local_url_checks(parsed: ParsedUrl) -> list[Evidence]:
    """Run every local (non-network) URL rule and collect the evidence.

    This is the single entry point the URL analyzer's HTTP-request-facing
    code should call for local checks. External provider checks (Google
    Safe Browsing, VirusTotal -- Steps 4-5) are separate and combined with
    this list at the call site (Step 6), since they involve network I/O
    and must be handled independently for availability.

    Lookalike and typosquatting detection are mutually exclusive per the
    Step 2 design: typosquatting is only checked if no lookalike match was
    found, to avoid double-counting the same underlying deception.
    """
    evidence: list[Evidence] = []

    lookalike = detect_lookalike_domain(parsed)
    if lookalike is not None:
        evidence.append(lookalike)
    else:
        typosquat = detect_typosquatting(parsed)
        if typosquat is not None:
            evidence.append(typosquat)

    for check in (detect_insecure_http, detect_ip_hostname, detect_high_risk_tld, detect_shortened_link):
        result = check(parsed)
        if result is not None:
            evidence.append(result)

    return evidence
