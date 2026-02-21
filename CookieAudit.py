from __future__ import annotations

import re
from typing import Any

TRACKER_PATTERNS = {
    "analytics": [r"_ga", r"_gid", r"_gat", r"analytics", r"mixpanel", r"amplitude", r"segment"],
    "advertising": [r"_fbp", r"doubleclick", r"ad[sx]?", r"ttclid", r"gcl_au", r"criteo"],
    "session": [r"session", r"sess", r"csrf", r"auth", r"token"],
    "functional": [r"pref", r"lang", r"theme", r"remember"],
}

DISCLOSURE_TERMS = {
    "analytics": ["analytics", "measurement", "google analytics", "mixpanel", "amplitude", "segment"],
    "advertising": ["advertising", "ad network", "targeted ads", "remarketing", "doubleclick", "facebook pixel"],
    "session": ["strictly necessary", "essential cookies", "authentication", "session cookies"],
    "functional": ["preferences", "functional cookies", "site settings", "language settings"],
}


def parse_observed_cookies(raw_text: str) -> list[str]:
    if not raw_text:
        return []

    tokens = [part.strip() for part in re.split(r"[\n,;]+", raw_text) if part.strip()]
    names: list[str] = []

    for token in tokens:
        if "=" in token:
            token = token.split("=", 1)[0].strip()
        if token:
            names.append(token)

    return sorted(set(names), key=str.lower)


def classify_cookie(cookie_name: str) -> str:
    lower = cookie_name.lower()
    for category, patterns in TRACKER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower):
                return category
    return "unknown"


def _policy_disclosures(policy_text: str) -> dict[str, bool]:
    text = policy_text.lower()
    disclosed: dict[str, bool] = {}
    for category, terms in DISCLOSURE_TERMS.items():
        disclosed[category] = any(term in text for term in terms)
    return disclosed


def grade_cookie_truthfulness(
    policy_text: str,
    observed_cookie_text: str,
    consent_state: str,
) -> dict[str, Any]:
    cookie_names = parse_observed_cookies(observed_cookie_text)
    classifications = [
        {"name": name, "category": classify_cookie(name)}
        for name in cookie_names
    ]

    category_counts = {"analytics": 0, "advertising": 0, "session": 0, "functional": 0, "unknown": 0}
    for item in classifications:
        category_counts[item["category"]] += 1

    disclosed = _policy_disclosures(policy_text)

    issues: list[dict[str, str]] = []
    score = 100

    non_essential_count = category_counts["analytics"] + category_counts["advertising"]

    if consent_state in {"before_consent", "after_reject"} and non_essential_count > 0:
        score -= min(45, non_essential_count * 12)
        issues.append(
            {
                "severity": "high",
                "title": "Non-essential cookies loaded before consent",
                "detail": "Analytics/advertising cookies were observed when they should usually be blocked.",
            }
        )

    if category_counts["analytics"] > 0 and not disclosed.get("analytics", False):
        score -= 20
        issues.append(
            {
                "severity": "high",
                "title": "Undisclosed analytics tracking",
                "detail": "Analytics-like cookies were observed but analytics disclosure language is weak or missing.",
            }
        )

    if category_counts["advertising"] > 0 and not disclosed.get("advertising", False):
        score -= 25
        issues.append(
            {
                "severity": "high",
                "title": "Undisclosed advertising tracking",
                "detail": "Ad/remarketing-like cookies were observed but advertising disclosure language is weak or missing.",
            }
        )

    if category_counts["unknown"] > 3:
        score -= 10
        issues.append(
            {
                "severity": "medium",
                "title": "Many unknown cookies",
                "detail": "Several cookies could not be classified; manually verify vendor and purpose.",
            }
        )

    if "opt-out" not in policy_text.lower() and "do not sell" not in policy_text.lower():
        score -= 8
        issues.append(
            {
                "severity": "medium",
                "title": "Weak opt-out language",
                "detail": "Policy text does not clearly mention opt-out or Do Not Sell controls.",
            }
        )

    score = max(0, min(100, score))

    if score >= 85:
        grade = "A"
        risk_level = "Low"
    elif score >= 70:
        grade = "B"
        risk_level = "Low"
    elif score >= 55:
        grade = "C"
        risk_level = "Medium"
    elif score >= 40:
        grade = "D"
        risk_level = "High"
    else:
        grade = "F"
        risk_level = "High"

    issues.sort(key=lambda item: {"high": 0, "medium": 1, "low": 2}.get(item["severity"], 3))

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "issues": issues,
        "cookies": classifications,
        "category_counts": category_counts,
        "consent_state": consent_state,
    }
