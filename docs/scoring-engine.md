# SafeCheck Scoring Engine (v1) — Shared Contract for Web and Android

Status: Frozen. This document is the cross-platform source of truth for risk scoring. The web backend (this repository) and the Android app should each implement their own analyzer code, but both must produce scores and bands that agree given the same evidence. Any change here must be updated in both platforms simultaneously.

## 1. Core principle

Analyzers produce evidence. Evidence carries points. The risk engine sums points per category, caps each category, sums the categories, and clips the total at 100. The engine — not the LLM, not any single analyzer — makes the final score.

```text
score = min(100, Rule_points + URL_points + ML_points)
```

Each category is independently capped before summing:

```text
Rule_points = min(45, sum of all rule-engine evidence points)
URL_points  = min(35, sum of all URL/domain-reputation evidence points)
ML_points   = min(20, sum of all LLM-derived archetype evidence points)
```

Category caps sum to exactly 100, so no single category can saturate the score on its own, and the final `min(100, ...)` clip is a safety net rather than the primary bound.

## 2. Why these three categories, and why these caps

| Category | Cap | Rationale |
|---|---|---|
| Rule_points | 45 | Our two primary features — email and document analysis — produce mostly deterministic, rule-based evidence (urgency language, credential requests, impersonation, document claim mismatches, fake offers). This is our richest and most trustworthy evidence source, so it gets the largest share. |
| URL_points | 35 | URL/domain reputation (lookalike domains, high-risk TLDs, HTTP-only, Google Safe Browsing, VirusTotal) is strong evidence when present, but not every case involves a URL at all. |
| ML_points | 20 | LLM-derived semantic classification is corroborating, not authoritative. Per our architecture, the LLM must never determine the score directly — it only outputs structured signals that the rule engine converts into points, capped low so it cannot dominate. |

Document-analysis evidence (claim extraction, official-source verification, fee/deadline mismatches) contributes through `Rule_points`. It does not get a separate category in this version.

## 3. Risk bands (4-band, matches Android)

```typescript
export type RiskBand = "LOW" | "UNCERTAIN" | "MEDIUM" | "HIGH";

export function calculateRiskBand(score: number): RiskBand {
  if (score >= 75) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 25) return "UNCERTAIN";
  return "LOW";
}
```

| Band | Score range | Meaning |
|---|---|---|
| LOW | 0–24 | No meaningful evidence of fraud found |
| UNCERTAIN | 25–39 | Some suspicious signals, but not enough to confidently flag as risky |
| MEDIUM | 40–74 | Multiple corroborating signals; caution warranted |
| HIGH | 75–100 | Strong, corroborated evidence of fraud |

This replaces the 3-band LOW/MEDIUM/HIGH scale used in the Phase 1 draft of `docs/api-contract.md`. `docs/api-contract.md` has been updated to match (see Section 8 below).

## 4. Evidence schema

Every signal produced by any analyzer — rule engine, URL analyzer, document analyzer, or LLM-derived classifier — must be expressed in this shape before reaching the risk engine:

```typescript
interface Evidence {
  evidenceId: string;
  category: "rules" | "url" | "ml";
  signal: string;             // e.g. "URGENT_PAYMENT", "LOOKALIKE_DOMAIN"
  points: number;
  reason: string;              // human-readable explanation
  observedValue: string;       // the actual matched text/domain/etc.
  confidence: number;          // 0.0–1.0
  correlationGroup: string;    // groups related evidence, e.g. "CORR_URGENCY"
  source: string;              // e.g. "rule_engine", "google_safe_browsing", "gemini_intent"
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  availability: "available" | "unavailable";
}
```

Rules:

- `availability: "unavailable"` evidence must always carry `points: 0`. An unreachable provider (Google Safe Browsing down, VirusTotal quota exceeded, LLM timeout) is never treated as a positive signal of fraud.
- The sum of all evidence `points` within a category must exactly equal that category's reported sub-score. If a normalization step is needed to make individual evidence cards add up to a pre-capped sub-score, use proportional scaling (see Section 6), never silent truncation.

## 5. Portable shared configuration (identical values on both platforms)

These are data tables, not code. Both the web backend and the Android app should load these from an identical shared config file (e.g. `shared/fraud-config.json`) rather than hardcoding them separately in each codebase, so a future update only has to happen once.

### 5.1 PII redaction patterns

| Identifier | Regex | Semantic placeholder |
|---|---|---|
| Password | `(?i)\b(password\|passwd\|pwd)\b\s*(?:is\|:\|=)?\s*(\S+)` | `[PASSWORD]` |
| PIN / MPIN | `(?i)\b(pin\|mpin\|upi\s*pin)\b\s*(?:is\|:\|=)?\s*(\d{4,6})` | `[PIN]` |
| OTP | `(?i)\b(otp\|verification\s*code\|code)\b\s*(?:is\|:\|=)?\s*(\d{4,8})` | `[OTP]` |
| IFSC Code | `\b[A-Z]{4}0[A-Z0-9]{6}\b` | `[IFSC]` |
| PAN Card | `\b[A-Z]{5}[0-9]{4}[A-Z]\b` | `[PAN]` |
| UPI ID / VPA | `\b([\w.\-]{2,})@([a-zA-Z]{2,})\b` | `[UPI_ID]` |
| Credit/Debit Card | `\b(?:\d[ -]?){12,18}\d\b` | `[CARD_NUMBER]` |
| Aadhaar Number | `\b\d{4}[ -]?\d{4}[ -]?\d{4}\b` | `[AADHAAR]` |
| Bank Account | `\b\d{9,18}\b` | `[ACCOUNT_NUMBER]` |
| Amount | `(?i)(?:Rs\.?\|INR\|₹)\s*[0-9,]+(?:\.[0-9]{1,2})?` | `[AMOUNT]` (unmasked in display, tagged for LLM) |

Redaction happens before content reaches the LLM, logs, or any external API. This applies identically to email bodies, document text, and URL query strings where applicable.

### 5.2 Brand → official domain map (for lookalike detection)

```json
{
  "sbi": ["sbi.co.in", "onlinesbi.sbi"],
  "onlinesbi": ["sbi.co.in", "onlinesbi.sbi"],
  "yono": ["sbi.co.in", "onlinesbi.sbi"],
  "hdfc": ["hdfcbank.com"],
  "hdfcbank": ["hdfcbank.com"],
  "icici": ["icicibank.com"],
  "icicibank": ["icicibank.com"],
  "axis": ["axisbank.com"],
  "axisbank": ["axisbank.com"],
  "incometax": ["incometax.gov.in"],
  "cybercrime": ["cybercrime.gov.in"],
  "indiapost": ["indiapost.gov.in"],
  "amazon": ["amazon.in"],
  "flipkart": ["flipkart.com"]
}
```

This list should grow over time based on what our test cases and real usage reveal. It is intentionally the same list both platforms consult.

### 5.3 Lookalike-domain algorithm

1. If the domain matches a brand's official domain (or a valid subdomain of it) → clean, no evidence.
2. If a brand name appears with a deceptive separator (`sbi-`, `-sbi-`, `-sbi`) in the SLD → `LOOKALIKE_DOMAIN` evidence.
3. If a brand name appears as a deceptive subdomain of an unrelated host (`sbi.something-else.com`) → `LOOKALIKE_DOMAIN` evidence.
4. If Levenshtein edit distance between the SLD and a known brand name is ≤2, and the lengths are within [-2, +3] characters of each other → `TYPOSQUATTING` evidence.

### 5.4 High-risk TLD list

```text
.xyz .top .click .link .zip .ru .surf .work .rest .country .vip .fit .tokyo .kim .su .cfd
```

## 6. Evidence normalization (when card points must sum exactly to a sub-score)

If a category's raw evidence sum doesn't exactly equal its capped sub-score (e.g. raw rule evidence totals 52 but the cap is 45), scale proportionally rather than truncating arbitrarily:

```typescript
function normalizeEvidence(evidenceList: Evidence[], targetTotal: number): Evidence[] {
  if (!evidenceList.length || targetTotal === 0) return [];

  const rawSum = evidenceList.reduce((acc, ev) => acc + ev.points, 0);
  if (rawSum <= targetTotal) return evidenceList; // no scaling needed if already under cap

  let scaled = evidenceList.map(ev => ({
    ...ev,
    points: Math.max(1, Math.floor((ev.points / rawSum) * targetTotal)),
  }));

  const currentSum = scaled.reduce((acc, ev) => acc + ev.points, 0);
  const diff = targetTotal - currentSum;
  if (diff !== 0 && scaled.length > 0) {
    scaled[scaled.length - 1].points = Math.max(1, scaled[scaled.length - 1].points + diff);
  }

  return scaled;
}
```

Note the difference from a naive implementation: normalization only triggers when the raw sum *exceeds* the cap. If evidence naturally totals less than the cap, it is left alone — we do not inflate weak evidence to hit a target score.

## 7. LLM-derived evidence (ML category, capped at 20)

The LLM never assigns its own point values. It returns a structured, boolean/enum classification; the rule engine looks up a fixed point value for each flag the LLM sets to `true`, and the category caps at 20 regardless of how many flags fire.

### 7.1 Scam archetype taxonomy (from LLM classification)

| Archetype flag | Points if true | Notes |
|---|---|---|
| `digital_arrest_or_police` | 20 | Alone reaches the ML cap — this is the most severe extortion pattern |
| `investment_scam` | 15 | Ponzi/crypto/investment fraud framing |
| `job_task_scam` | 15 | Advance-fee job/task scam framing |
| `loan_fraud` | 12 | Predatory instant-loan framing |
| `delivery_customs_scam` | 12 | Fake parcel/customs fee framing |
| `banking_phishing` | 10 | Generic bank impersonation intent, distinct from URL-based lookalike detection |
| `lottery_scam` | 10 | Lottery/prize framing |
| `betting_gambling` | 8 | Unregulated betting/gambling promotion |

Multiple flags may fire; their points sum and are then capped at 20 via the normalization rule in Section 6.

### 7.2 LLM output contract (structured, validated before use)

```json
{
  "risk_indicators": {
    "urgency": true,
    "money_involved": true,
    "credential_request": false,
    "impersonation": true,
    "digital_arrest_or_police": false,
    "job_task_scam": false,
    "investment_scam": false,
    "loan_fraud": false,
    "lottery_scam": false,
    "betting_gambling": false,
    "banking_phishing": true,
    "delivery_customs_scam": false
  },
  "identified_tactics": ["urgent account threat", "unofficial verification link"],
  "summary": "This message impersonates a bank and pressures immediate action.",
  "confidence": 0.9
}
```

The backend validates this shape (e.g. with Pydantic) before converting flags to evidence. If the LLM fails, times out, or returns an invalid shape, `ML_points = 0` with an `unavailable` evidence entry — the case still proceeds using Rule_points and URL_points alone.

## 8. Relationship to `docs/api-contract.md`

`docs/api-contract.md` has been updated so that `risk.band` documents all four values (`LOW`, `UNCERTAIN`, `MEDIUM`, `HIGH`) instead of the original three-band draft. The `evidence[]` array in API responses should use the richer schema from Section 4 of this document (adding `category`, `correlationGroup`, `severity` alongside the fields already specified in the API contract).

## 9. What was deliberately not adopted from the reference Android architecture document

- **Hardcoded tier-override scores** (e.g. "if this pattern matches, force score = 85"): rejected. Our engine always computes the score forward from evidence; it never works backward from a pre-decided target score for a named scenario.
- **LLM directly assigning point values**: rejected. The LLM outputs boolean/enum classifications only; the rule engine assigns points per flag.
- **Device/OS integrity auditing** (root detection, sideloaded-APK checks, accessibility-service abuse scanning): not applicable to a website; this is an Android-only concern and out of scope here.
