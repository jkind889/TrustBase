# TrustBase

TrustBase is a Flask-based privacy intelligence app that audits a website using:

- policy/TOS language analysis,
- cookie behavior checks,
- optional AI breach snapshot generation,
- and a final averaged grade.

It is designed for fast, practical trust/compliance reviews from a single URL input.

---

## Features

- **Policy Risk Audit**
	- Detects risky privacy language categories (collection, sharing, rights, retention, vague terms).
	- Highlights risky terms in policy text.
	- Produces a policy grade + risk level.

- **Cookie Compliance Audit**
	- Collects observed cookies for a site.
	- Compares behavior against policy disclosures.
	- Produces cookie compliance score + grade.

- **Optional AI Breach Snapshot**
	- Toggle-able checkbox to reduce token usage.
	- Generates structured incident summaries with source links and synopsis.
	- Produces breach grade + risk level.

- **Final TrustBase Grade**
	- Averages available component grades:
		- Policy,
		- Cookie,
		- and optional Breach.

---

## Tech Stack

- Python 3.10+
- Flask
- Playwright (for cookie collection)
- Google GenAI SDK (`google-genai`)
- BeautifulSoup + requests

---

## Quick Start (Windows PowerShell)

1. **Create and activate virtual environment**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. **Install dependencies**

```powershell
pip install -r requirements.txt
```

3. **Install Playwright browser runtime**

```powershell
playwright install chromium
```

4. **Set environment variables**

Create/edit `.env`:

```env
GEMINI_API_KEY=your_real_api_key_here
```

5. **Run app**

```powershell
python app.py
```

Open:

- `http://127.0.0.1:5000/` (Home)
- `http://127.0.0.1:5000/compare` (Main audit workflow)

---

## API Key Test Utility

You can test your Gemini key via CLI:

```powershell
python test_key.py
```

This script auto-discovers models from your account and falls back across candidates.

---

## Routes

- `/` → Home page
- `/about` → Product/function glossary and grading documentation
- `/compare` → Primary TrustBase audit page
- `/cookie-audit` → Alias of the same audit workflow
- `/test-key` and `/test_key.html` → Web key test page

---

## Grading Model (Current)

- Letter-to-points mapping: `A=4, B=3, C=2, D=1, F=0`
- Final grade = average of available component grades
- Final risk level:
	- `A/B` → Low
	- `C` → Medium
	- `D/F` → High

Component grades include:

- Policy grade (from policy risk score)
- Cookie grade (from cookie compliance score)
- Breach grade (if AI breach lookup is enabled)

---

## Project Structure

- `app.py` — Flask app, routes, grading aggregation, AI breach integration
- `Parser.py` — policy term detection and risk scoring logic
- `CookieAudit.py` — cookie classification, policy fetch, cookie truthfulness logic
- `test_key.py` — CLI Gemini key/model connectivity test
- `templates/` — Jinja templates (`base`, `index`, `about`, `compare`, etc.)
- `static/style.css` — global UI styling
- `static/trustbase.png` — logo asset
- `requirements.txt` — Python dependencies

---

## Notes / Limitations

- AI breach summaries may vary by model output and available public info.
- Always validate critical legal/compliance findings with human review.
- Some sites aggressively block crawling/automation; cookie or policy fetch can fail per-site.

---

## License

No license has been specified yet.
