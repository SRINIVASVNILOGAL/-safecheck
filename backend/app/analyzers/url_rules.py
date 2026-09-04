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

import Levenshtein

from app.analyzers.url_config import (
    get_brand_domain_map,
    get_levenshtein_length_window,
    get_levenshtein_max_distance,
)
from app.analyzers.url_parser import ParsedUrl
from app.risk.evidence import Evidence

LOOKALIKE_POINTS = 25
TYPOSQUATTING_POINTS = 25


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
