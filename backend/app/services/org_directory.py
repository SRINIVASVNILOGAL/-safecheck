"""Static, deterministic official fraud-reporting contact directory.

This directory is intentionally NOT LLM-generated: helpline numbers and
report-fraud email addresses are exactly the kind of fact an LLM must
never invent (a hallucinated helpline number is actively dangerous). Every
entry below was verified against the organization's own official page
(see the `source_url` on each entry) as of Sep 2026. If an entry goes
stale, it must be corrected here directly, not "fixed" by asking an LLM
to look it up at request time.

Matching is a simple case-insensitive keyword search over the analyzed
message's sender/subject/body/pasted text -- deliberately dumb and
predictable rather than an LLM-based classifier, so the same input always
identifies the same organization.

The National Cyber Crime Reporting Portal / helpline (1930) is always
included as a fallback: every fraud report in India can be filed there
regardless of which specific organization was impersonated, and it is
included even for banks/IRCTC (users are meant to file with the impacted
organization first, but often also file with 1930/cybercrime.gov.in).
"""

from __future__ import annotations

from pydantic import BaseModel


class OrgContact(BaseModel):
    """One official reporting channel. `email` is the report-fraud address
    to send a drafted report to; it is None when the organization only
    offers a phone helpline and/or a web portal (no direct email SafeCheck
    should draft a message to).
    """

    key: str
    display_name: str
    email: str | None = None
    phone: str | None = None
    portal_url: str | None = None
    source_url: str
    note: str = ""


NATIONAL_CYBERCRIME = OrgContact(
    key="NATIONAL_CYBERCRIME",
    display_name="National Cyber Crime Reporting Portal (Government of India)",
    email=None,
    phone="1930",
    portal_url="https://www.cybercrime.gov.in/",
    source_url="https://www.cybercrime.gov.in/Webform/Accept.aspx",
    note="Files a formal police complaint. Fastest fund-recovery odds when reported within 60-90 minutes of a fraudulent payment.",
)

_DIRECTORY: list[tuple[frozenset[str], OrgContact]] = [
    (
        frozenset({"sbi", "state bank of india"}),
        OrgContact(
            key="SBI",
            display_name="State Bank of India (SBI)",
            email="customercare@sbi.co.in",
            phone="1800-1234 / 1800-2100 / 080-26599990",
            portal_url="https://sbi.co.in/web/customer-care/contact-us",
            source_url="https://sbi.co.in/web/customer-care/contact-us",
        ),
    ),
    (
        frozenset({"icici", "icici bank"}),
        OrgContact(
            key="ICICI",
            display_name="ICICI Bank",
            email="antiphishing@icicibank.com",
            phone="1800-1080",
            portal_url="https://www.icicibank.com/personal-banking/products/online-safe-banking/report-fraud",
            source_url="https://www.icicibank.com/personal-banking/products/online-safe-banking/report-fraud",
        ),
    ),
    (
        frozenset({"hdfc", "hdfc bank"}),
        OrgContact(
            key="HDFC",
            display_name="HDFC Bank",
            email="report.phishing@hdfcbank.com",
            phone="1800-258-6161",
            portal_url="https://www.hdfcbank.com/personal/useful-links/important-messages/reporting-of-suspicious-fraudulent-communication",
            source_url="https://www.hdfcbank.com/personal/useful-links/important-messages/reporting-of-suspicious-fraudulent-communication",
        ),
    ),
    (
        frozenset({"irctc", "indian railway", "indian railways", "railway", "railways"}),
        OrgContact(
            key="IRCTC",
            display_name="IRCTC / Indian Railways",
            email="etickets@irctc.co.in",
            phone="139 / 14646",
            portal_url="https://contents.irctc.co.in/en/ContactUsEn.html",
            source_url="https://contents.irctc.co.in/en/ContactUsEn.html",
            note="etickets@irctc.co.in only accepts email sent from the traveler's own registered IRCTC email address.",
        ),
    ),
    (
        frozenset({"karnataka", "bengaluru", "bangalore", "karnataka state government", "ksp"}),
        OrgContact(
            key="KARNATAKA_CYBER_POLICE",
            display_name="Karnataka State Police -- Cyber Crime Police Station",
            email="ccps@ksp.gov.in",
            phone="1930",
            portal_url="https://ccps.karnatakastatepolice.org/",
            source_url="https://ccps.karnatakastatepolice.org/",
        ),
    ),
]


def identify_organizations(text: str) -> list[OrgContact]:
    """Return every directory entry whose keywords appear in `text`, plus
    the National Cyber Crime Reporting Portal as a guaranteed fallback.

    Order: specific organizations first (in directory order), then the
    national fallback last -- so the UI can label the first result
    "detected organization" and the rest as "also report to".
    """
    lowered = text.lower()
    matches = [contact for keywords, contact in _DIRECTORY if any(keyword in lowered for keyword in keywords)]
    matches.append(NATIONAL_CYBERCRIME)
    return matches
