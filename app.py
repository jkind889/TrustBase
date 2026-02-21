from flask import Flask, render_template, request
from Parser import analyze_policy_text
from CookieAudit import grade_cookie_truthfulness
from markupsafe import Markup, escape
import re

app = Flask(__name__)


def _severity_rank(level: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(level, 3)


def _extract_flaws(report: dict) -> list[dict]:
    flaws: list[dict] = []
    categories = report.get("categories", {})

    for category_name, category_data in categories.items():
        subgroups = category_data.get("subgroups", {})
        for subgroup_name, hits in subgroups.items():
            for hit in hits:
                term = hit.get("term", "")
                count = hit.get("count", 0)

                severity = "medium"
                if category_name.startswith("5."):
                    severity = "high"
                elif category_name.startswith("2."):
                    severity = "high"
                elif category_name.startswith("1.") and subgroup_name == "High-Risk Identifiers":
                    severity = "high"
                elif category_name.startswith("4.") and subgroup_name == "Timelines":
                    severity = "low"

                flaws.append(
                    {
                        "category": category_name,
                        "subgroup": subgroup_name,
                        "term": term,
                        "count": count,
                        "severity": severity,
                    }
                )

    flaws.sort(
        key=lambda item: (
            _severity_rank(item["severity"]),
            -item["count"],
            item["term"].lower(),
        )
    )
    return flaws


def _privacy_grade(score: int) -> str:
    if score >= 70:
        return "F"
    if score >= 55:
        return "D"
    if score >= 40:
        return "C"
    if score >= 25:
        return "B"
    return "A"


def _pattern_for_term(term: str) -> str:
    escaped = re.escape(term)
    escaped = escaped.replace(r"\ ", r"\s+")
    escaped = escaped.replace(r"\,", r"\s*,\s*")
    if re.fullmatch(r"[A-Za-z\-]+", term):
        return rf"\b{escaped}\b"
    return escaped


def _highlight_dangers(text: str, flaws: list[dict]) -> Markup:
    dangerous_terms = {
        flaw["term"]
        for flaw in flaws
        if flaw.get("severity") in {"high", "medium"}
    }
    if not dangerous_terms:
        return Markup(f"<pre class='policy-text'>{escape(text)}</pre>")

    patterns = sorted(
        (_pattern_for_term(term) for term in dangerous_terms),
        key=len,
        reverse=True,
    )
    combined_pattern = re.compile("(" + "|".join(patterns) + ")", flags=re.IGNORECASE)

    parts: list[str] = []
    cursor = 0
    for match in combined_pattern.finditer(text):
        start, end = match.span()
        if start > cursor:
            parts.append(str(escape(text[cursor:start])))
        parts.append(f"<mark class='danger-mark'>{escape(text[start:end])}</mark>")
        cursor = end
    if cursor < len(text):
        parts.append(str(escape(text[cursor:])))

    highlighted = "".join(parts)
    return Markup(f"<pre class='policy-text'>{highlighted}</pre>")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/cookie-audit", methods=["GET", "POST"])
def cookie_audit():
    policy_text = ""
    observed_cookies = ""
    consent_state = "before_consent"
    result = None

    if request.method == "POST":
        policy_text = request.form.get("policy_text", "").strip()
        observed_cookies = request.form.get("observed_cookies", "").strip()
        consent_state = request.form.get("consent_state", "before_consent")

        if policy_text and observed_cookies:
            result = grade_cookie_truthfulness(
                policy_text=policy_text,
                observed_cookie_text=observed_cookies,
                consent_state=consent_state,
            )

    return render_template(
        "cookie_audit.html",
        policy_text=policy_text,
        observed_cookies=observed_cookies,
        consent_state=consent_state,
        result=result,
    )

@app.route("/compare", methods=["GET", "POST"])
def compare():
    policy_text = ""
    report = None
    flaws = []
    highlighted_text = None
    grade = None

    if request.method == "POST":
        policy_text = request.form.get("policy_text", "").strip()

        if policy_text:
            report = analyze_policy_text(policy_text)
            flaws = _extract_flaws(report)
            highlighted_text = _highlight_dangers(policy_text, flaws)
            grade = _privacy_grade(report.get("risk_score", 0))

    return render_template(
        "compare.html",
        policy_text=policy_text,
        report=report,
        flaws=flaws,
        highlighted_text=highlighted_text,
        grade=grade,
    )

if __name__ == "__main__":
    app.run(debug=True)
