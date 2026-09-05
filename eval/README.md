# SafeCheck offline evaluation (not shipped, not part of scoring)

This folder holds an **offline false-positive/sanity check** for the deterministic
rule engine (`app.risk.rules`, `app.analyzers.url_rules`, `app.analyzers.text_url_extraction`).

## Why this exists

The user provided the public UCI/Kaggle "SMS Spam Collection" dataset (5,574
labeled `ham`/`spam` SMS messages, mostly 2005-era UK premium-rate spam).

It was reviewed and is **not suitable** as training data or as a fraud-category
benchmark, because:

- SafeCheck's rule engine is deterministic, not a trained model -- there is
  nothing here to "train."
- The dataset has only two labels (`ham`/`spam`); it has no fraud-category
  labels (OTP theft, bank impersonation, toll-fee scam, etc.), so it cannot
  validate SafeCheck's specific signal categories.
- Most of the `spam` messages are premium-rate ringtone/chat-line spam, not
  the fraud patterns SafeCheck targets, so spam recall against this set is
  not a meaningful product metric.

What it **is** useful for: the `ham` messages are thousands of real, messy,
casual conversational texts -- exactly the kind of text that could trigger a
false positive in urgency/payment/lottery-style regex rules. Running them
through the rule engine and checking the false-positive rate is a legitimate,
narrow regression check.

## Usage

```powershell
python eval/run_ham_spam_check.py
```

This is a standalone script. It is **not** imported by the application, is
**not** a test collected by pytest, and does not affect scoring, CI, or the
shipped product in any way. The CSV file is local evaluation data only.
