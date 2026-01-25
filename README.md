# Sentinel Logger

A web application designed for QA testers to analyze camera and hardware log files. Automatically detects errors, warnings, and issues, visualizes log data, and helps create bug reports efficiently.

## Features

### 1. Error Detection
- Automatically identifies and highlights errors, warnings, and critical issues
- Pattern-based detection for common camera/hardware problems:
  - Crashes and memory issues
  - Connection timeouts and network failures
  - Recording failures and frame drops
  - Storage errors and data corruption
  - Thermal issues and battery warnings
  - Lens and optical system errors

### 2. Search and Filter
- Full-text search across all log entries
- Filter by severity level (Critical, Error, Warning, Info, Debug)
- Filter by service (video, audio, network, storage, etc.)
- Time-based filtering
- Pagination for large log files

### 3. Bug Report Generation
- Create detailed bug reports from detected issues
- Multiple template formats:
  - Default (Markdown)
  - Jira
  - GitHub Issues
  - Minimal
- Auto-populated fields:
  - Title and description
  - Environment/device information
  - Log context and affected lines
  - Severity and category
- Export options: Markdown, JSON, Plain Text

### 4. Log Visualization
- Interactive charts powered by Chart.js:
  - Severity distribution (pie chart)
  - Errors over time (line chart)
  - Errors by service (bar chart)
  - Hourly error distribution
  - Issue categories

## Installation

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)

### Setup

1. Clone or download the project:
```bash
cd "/Users/alonmozes/qa tool"
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python main.py
```

5. Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## Usage

### Uploading Log Files
1. Click "Upload" in the navigation bar
2. Drag and drop a log file or click "Browse Files"
3. Supported formats: `.log`, `.txt`, `.csv`
4. Maximum file size: 500MB

### Analyzing Logs
1. After upload, the system automatically parses and analyzes the log
2. View the analysis dashboard showing:
   - Error and warning counts
   - Detected issues with severity
   - Log preview with filtering options

### Viewing Issues
1. Navigate to "Issues" to see all detected issues
2. Filter by severity or status
3. Click on an issue for detailed view with log context

### Creating Bug Reports
1. From an issue detail page, click "Create Bug Report"
2. Select a template format
3. Add reproduction steps and additional context
4. Export or copy the report

### Viewing Charts
1. From the analysis page, click "Charts"
2. Interactive visualizations show:
   - Error distribution
   - Timeline trends
   - Service-level analysis

## Project Structure

```
qa tool/
|-- main.py                 # Application entry point
|-- config.py               # Configuration settings
|-- requirements.txt        # Python dependencies
|-- README.md               # This file
|-- app/
|   |-- __init__.py         # Flask application factory
|   |-- models/
|   |   |-- __init__.py     # Database models
|   |-- routes/
|   |   |-- __init__.py     # Blueprint registration
|   |   |-- views.py        # HTML view routes
|   |   |-- api.py          # REST API endpoints
|   |-- services/
|   |   |-- __init__.py     # Service exports
|   |   |-- log_parser.py   # Log parsing engine
|   |   |-- issue_detector.py   # Issue detection
|   |   |-- bug_report_generator.py  # Bug report creation
|   |   |-- analytics.py    # Chart data generation
|   |-- templates/          # HTML templates
|   |-- static/
|       |-- css/style.css   # Custom styles
|       |-- js/main.js      # JavaScript utilities
|-- uploads/                # Uploaded log files
|-- sample_logs/            # Sample log files for testing
```

## API Endpoints

### Log Files
- `GET /api/log-files` - List all log files
- `GET /api/log-files/<id>` - Get log file details
- `GET /api/log-files/<id>/entries` - Get log entries with pagination
- `GET /api/log-files/<id>/issues` - Get issues for a log file
- `GET /api/log-files/<id>/charts` - Get chart data
- `GET /api/log-files/<id>/stats` - Get statistics

### Issues
- `GET /api/issues` - List all issues
- `GET /api/issues/<id>` - Get issue details
- `PATCH /api/issues/<id>` - Update issue status
- `GET /api/issues/<id>/context` - Get log context for issue

### Bug Reports
- `GET /api/bug-reports` - List all bug reports
- `GET /api/bug-reports/<id>` - Get bug report details
- `POST /api/bug-reports` - Create a new bug report

### Search
- `GET /api/search?q=<query>` - Search log entries
- `GET /api/services` - List unique services

## Log Format Support

The parser supports various log formats commonly used in camera/hardware testing:

### Timestamp Formats
- ISO 8601: `2024-01-15T14:30:25.123Z`
- Standard: `2024-01-15 14:30:25`
- US format: `01/15/2024 14:30:25`
- Time only: `14:30:25.123`

### Severity Levels
- CRITICAL / CRIT / FATAL
- ERROR / ERR / FAIL
- WARNING / WARN
- INFO / NOTICE
- DEBUG / TRACE

### Detected Services
- video-service
- audio-service
- network-service
- storage-service
- firmware-service
- sensor-service
- power-service
- lens-service
- image-processor
- ui-service

## Configuration

Edit `config.py` to customize:

```python
class Config:
    SECRET_KEY = 'your-secret-key'
    UPLOAD_FOLDER = Path('uploads')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
    ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}
```

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: Bootstrap 5, Chart.js
- **Log Parsing**: Custom regex-based parser with chardet for encoding detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - feel free to use and modify for your QA testing needs.
