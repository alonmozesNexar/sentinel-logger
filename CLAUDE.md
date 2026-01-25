# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sentinel Logger - A web application for QA testers to analyze camera/hardware log files, detect issues, and generate bug reports.

## Commands

```bash
# Setup (first time)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the application
source venv/bin/activate
python main.py
# Opens at http://127.0.0.1:5000
```

## Architecture

**Flask application with SQLite database.**

```
app/
├── __init__.py          # Flask app factory, creates app and db
├── models/              # SQLAlchemy models: LogFile, LogEntry, Issue, BugReport
├── routes/
│   ├── views.py         # HTML page routes (upload, dashboard, charts, bug reports)
│   └── api.py           # REST API endpoints for AJAX operations
├── services/
│   ├── log_parser.py    # Parses plain text log files, extracts entries with timestamps
│   ├── issue_detector.py # Pattern-based detection (crashes, timeouts, memory issues)
│   ├── bug_report_generator.py # Generates reports in Jira/GitHub/Markdown formats
│   └── analytics.py     # Aggregates data for Chart.js visualizations
├── templates/           # Jinja2 HTML templates
└── static/              # CSS and JavaScript
```

**Key data flow:**
1. User uploads `.log` file → `log_parser.py` extracts entries
2. `issue_detector.py` scans entries for error patterns, assigns severity
3. Results stored in SQLite, displayed via templates
4. User can generate bug reports from detected issues

## Configuration

- `config.py` - App settings (upload folder, database path, max file size)
- Database: `instance/app.db` (SQLite, auto-created on first run)
- Uploads stored in: `uploads/`
