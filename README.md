# Basic Flask App

## Setup

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the app:

```powershell
python app.py
```

Then open http://127.0.0.1:5000

## Project structure

- `app.py` - Flask application entrypoint
- `templates/base.html` - Shared layout template
- `templates/index.html` - Home page template rendered at `/`
- `templates/about.html` - About page template rendered at `/about`
- `static/style.css` - Stylesheet for the home page
