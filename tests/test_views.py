"""
Test suite for Sentinel Logger view routes
Tests all 21 routes defined in app/routes/views.py
"""
import pytest
import tempfile
import os
import json
from pathlib import Path
from io import BytesIO
from datetime import datetime
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import LogFile, LogEntry, Issue, BugReport


class TestConfig:
    """Test configuration"""
    TESTING = True
    SECRET_KEY = 'test-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = None  # Will be set dynamically per test
    ALLOWED_EXTENSIONS = None  # Allow all files
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024
    CAMERA_DEFAULT_IP = '192.168.50.1'
    CAMERA_DEFAULT_USER = 'root'
    CAMERA_DEFAULT_PASSWORD = 'root'
    CAMERA_LOG_PATH = '/var/log/messages'
    CAMERA_SSH_PORT = 22
    CAMERA_SSH_TIMEOUT = 30


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create a temporary directory for uploads
    temp_dir = tempfile.mkdtemp()
    TestConfig.UPLOAD_FOLDER = Path(temp_dir)

    # Create app with test config
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from config import config

    # Patch the config module to use test config
    app = Flask(__name__, template_folder='../app/templates', static_folder='../app/static')
    app.config.from_object(TestConfig)
    app.config['UPLOAD_FOLDER'] = Path(temp_dir)

    db.init_app(app)

    # Register custom Jinja2 filters
    @app.template_filter('from_json')
    def from_json_filter(value):
        if value is None:
            return []
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []

    # Register blueprints
    from app.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    with app.app_context():
        db.create_all()

    yield app

    # Cleanup
    with app.app_context():
        db.drop_all()

    # Remove temp directory
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's CLI commands."""
    return app.test_cli_runner()


@pytest.fixture
def sample_log_file(app):
    """Create a sample log file in the database and on disk."""
    with app.app_context():
        # Create physical file
        upload_folder = app.config['UPLOAD_FOLDER']
        filename = 'test_log.log'
        file_path = upload_folder / filename

        log_content = """2024-01-01 10:00:00 [INFO] System started
2024-01-01 10:00:01 [INFO] Initializing video service
2024-01-01 10:00:02 [ERROR] Failed to connect to camera
2024-01-01 10:00:03 [WARNING] Retrying connection
2024-01-01 10:00:04 [INFO] Connection established
2024-01-01 10:00:05 [CRITICAL] Memory allocation failed
"""
        with open(file_path, 'w') as f:
            f.write(log_content)

        # Create database record
        log_file = LogFile(
            filename=filename,
            original_filename='test_log.log',
            file_size=len(log_content),
            parsed=False
        )
        db.session.add(log_file)
        db.session.commit()

        file_id = log_file.id
        return file_id


@pytest.fixture
def parsed_log_file(app, sample_log_file):
    """Create a fully parsed log file with entries and issues."""
    with app.app_context():
        log_file = LogFile.query.get(sample_log_file)
        log_file.parsed = True
        log_file.total_lines = 6
        log_file.error_count = 2
        log_file.warning_count = 1
        log_file.info_count = 3

        # Create log entries
        entries_data = [
            {'line_number': 1, 'severity': 'INFO', 'message': 'System started', 'raw_content': '2024-01-01 10:00:00 [INFO] System started'},
            {'line_number': 2, 'severity': 'INFO', 'message': 'Initializing video service', 'raw_content': '2024-01-01 10:00:01 [INFO] Initializing video service'},
            {'line_number': 3, 'severity': 'ERROR', 'message': 'Failed to connect to camera', 'raw_content': '2024-01-01 10:00:02 [ERROR] Failed to connect to camera'},
            {'line_number': 4, 'severity': 'WARNING', 'message': 'Retrying connection', 'raw_content': '2024-01-01 10:00:03 [WARNING] Retrying connection'},
            {'line_number': 5, 'severity': 'INFO', 'message': 'Connection established', 'raw_content': '2024-01-01 10:00:04 [INFO] Connection established'},
            {'line_number': 6, 'severity': 'CRITICAL', 'message': 'Memory allocation failed', 'raw_content': '2024-01-01 10:00:05 [CRITICAL] Memory allocation failed'},
        ]

        for entry_data in entries_data:
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=entry_data['line_number'],
                severity=entry_data['severity'],
                message=entry_data['message'],
                raw_content=entry_data['raw_content'],
                service='video-service',
                component='camera'
            )
            db.session.add(entry)

        # Create an issue
        issue = Issue(
            log_file_id=log_file.id,
            title='Camera Connection Error',
            description='Failed to connect to camera',
            severity='ERROR',
            category='connection',
            occurrence_count=1,
            affected_lines=json.dumps([3]),
            context='Connection error context',
            confidence_score=0.9,
            status='open'
        )
        db.session.add(issue)
        db.session.commit()

        return log_file.id


@pytest.fixture
def sample_issue(app, parsed_log_file):
    """Return the ID of a sample issue."""
    with app.app_context():
        issue = Issue.query.filter_by(log_file_id=parsed_log_file).first()
        return issue.id


@pytest.fixture
def sample_bug_report(app, sample_issue):
    """Create a sample bug report."""
    with app.app_context():
        bug_report = BugReport(
            issue_id=sample_issue,
            title='Camera Connection Bug',
            description='Camera fails to connect on startup',
            steps_to_reproduce='1. Start system\n2. Observe camera connection',
            expected_behavior='Camera should connect',
            actual_behavior='Camera connection fails',
            severity='ERROR',
            environment=json.dumps({'device': 'test-device'}),
            log_snippets='2024-01-01 10:00:02 [ERROR] Failed to connect to camera'
        )
        db.session.add(bug_report)
        db.session.commit()
        return bug_report.id


# =============================================================================
# Route 1: index (/)
# =============================================================================
class TestIndexRoute:
    """Tests for the main dashboard route."""

    def test_index_get_empty(self, client):
        """Test index page with no log files."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Sentinel' in response.data or b'dashboard' in response.data.lower()

    def test_index_get_with_files(self, client, sample_log_file):
        """Test index page with existing log files."""
        response = client.get('/')
        assert response.status_code == 200

    def test_index_shows_statistics(self, client, parsed_log_file):
        """Test that index shows statistics when files are present."""
        response = client.get('/')
        assert response.status_code == 200


# =============================================================================
# Route 2: upload (/upload)
# =============================================================================
class TestUploadRoute:
    """Tests for the file upload route."""

    def test_upload_get(self, client):
        """Test upload page renders correctly."""
        response = client.get('/upload')
        assert response.status_code == 200

    def test_upload_post_no_file(self, client):
        """Test upload with no file selected."""
        response = client.post('/upload', data={}, follow_redirects=True)
        assert response.status_code == 200
        # Should show error flash message
        assert b'No file selected' in response.data

    def test_upload_post_empty_filename(self, client):
        """Test upload with empty filename."""
        data = {
            'file': (BytesIO(b''), '')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert response.status_code == 200
        assert b'No file selected' in response.data

    def test_upload_post_valid_file(self, client, app):
        """Test upload with valid log file."""
        log_content = b"2024-01-01 10:00:00 [INFO] Test log entry"
        data = {
            'file': (BytesIO(log_content), 'test.log')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=False)
        # Should redirect to analyze page
        assert response.status_code == 302
        assert '/analyze/' in response.location

    def test_upload_post_creates_db_record(self, client, app):
        """Test that upload creates a database record."""
        log_content = b"2024-01-01 10:00:00 [INFO] Test log entry"
        data = {
            'file': (BytesIO(log_content), 'database_test.log')
        }
        client.post('/upload', data=data, content_type='multipart/form-data')

        with app.app_context():
            log_file = LogFile.query.filter_by(original_filename='database_test.log').first()
            assert log_file is not None
            assert log_file.file_size == len(log_content)


# =============================================================================
# Route 3: paste_log (/paste-log)
# =============================================================================
class TestPasteLogRoute:
    """Tests for the paste log content route."""

    def test_paste_log_empty_content(self, client):
        """Test paste with empty content."""
        response = client.post('/paste-log', data={
            'log_name': 'test',
            'log_content': ''
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'No log content provided' in response.data

    def test_paste_log_valid_content(self, client, app):
        """Test paste with valid content."""
        response = client.post('/paste-log', data={
            'log_name': 'pasted_test',
            'log_content': '2024-01-01 10:00:00 [INFO] Test pasted log'
        }, follow_redirects=False)
        assert response.status_code == 302
        assert '/analyze/' in response.location

    def test_paste_log_adds_extension(self, client, app):
        """Test that .log extension is added if missing."""
        client.post('/paste-log', data={
            'log_name': 'no_extension',
            'log_content': 'Test content'
        })

        with app.app_context():
            log_file = LogFile.query.first()
            assert log_file.filename.endswith('.log')

    def test_paste_log_sanitizes_filename(self, client, app):
        """Test that filename is sanitized."""
        client.post('/paste-log', data={
            'log_name': '../../../etc/passwd',
            'log_content': 'Test content'
        })

        with app.app_context():
            log_file = LogFile.query.first()
            assert '..' not in log_file.filename


# =============================================================================
# Route 4: camera_download (/camera-download)
# =============================================================================
class TestCameraDownloadRoute:
    """Tests for the camera download route."""

    def test_camera_download_get(self, client):
        """Test camera download page renders correctly."""
        response = client.get('/camera-download')
        assert response.status_code == 200

    def test_camera_download_shows_defaults(self, client):
        """Test that default camera settings are shown."""
        response = client.get('/camera-download')
        assert response.status_code == 200
        # Default IP should be present
        assert b'192.168.50.1' in response.data

    @patch('app.routes.views.CameraDownloader')
    def test_camera_download_post_failure(self, mock_downloader, client):
        """Test camera download with connection failure."""
        mock_instance = MagicMock()
        mock_instance.download_log.return_value = (None, 'Connection failed')
        mock_downloader.return_value = mock_instance

        response = client.post('/camera-download', data={
            'camera_ip': '192.168.1.1',
            'username': 'root',
            'password': 'root',
            'log_path': '/var/log/messages',
            'port': '22'
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Download failed' in response.data or b'error' in response.data.lower()


# =============================================================================
# Route 5: camera_test (/camera-test)
# =============================================================================
class TestCameraTestRoute:
    """Tests for the camera connection test route."""

    @patch('app.routes.views.CameraDownloader')
    def test_camera_test_success(self, mock_downloader, client):
        """Test camera connection test success."""
        mock_instance = MagicMock()
        mock_instance.test_connection.return_value = (True, 'Connection successful')
        mock_downloader.return_value = mock_instance

        response = client.post('/camera-test', data={
            'camera_ip': '192.168.1.1',
            'username': 'root',
            'password': 'root',
            'port': '22'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True

    @patch('app.routes.views.CameraDownloader')
    def test_camera_test_failure(self, mock_downloader, client):
        """Test camera connection test failure."""
        mock_instance = MagicMock()
        mock_instance.test_connection.return_value = (False, 'Connection refused')
        mock_downloader.return_value = mock_instance

        response = client.post('/camera-test', data={
            'camera_ip': '192.168.1.1',
            'username': 'root',
            'password': 'root',
            'port': '22'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == False


# =============================================================================
# Route 6: camera_info (/camera-info)
# =============================================================================
class TestCameraInfoRoute:
    """Tests for the camera info route."""

    @patch('app.routes.views.CameraDownloader')
    def test_camera_info_success(self, mock_downloader, client):
        """Test camera info retrieval success."""
        mock_instance = MagicMock()
        mock_instance.get_camera_info.return_value = ({'hostname': 'camera1'}, None)
        mock_downloader.return_value = mock_instance

        response = client.post('/camera-info', data={
            'camera_ip': '192.168.1.1',
            'username': 'root',
            'password': 'root',
            'port': '22'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'info' in data


# =============================================================================
# Route 7: camera_list_logs (/camera-list-logs)
# =============================================================================
class TestCameraListLogsRoute:
    """Tests for the camera list logs route."""

    @patch('app.routes.views.CameraDownloader')
    def test_camera_list_logs_success(self, mock_downloader, client):
        """Test listing log files on camera."""
        mock_instance = MagicMock()
        mock_instance.list_log_files.return_value = (['/var/log/messages'], None)
        mock_downloader.return_value = mock_instance

        response = client.post('/camera-list-logs', data={
            'camera_ip': '192.168.1.1',
            'username': 'root',
            'password': 'root',
            'port': '22',
            'directory': '/var/log'
        })

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'files' in data


# =============================================================================
# Route 8: analyze (/analyze/<int:file_id>)
# =============================================================================
class TestAnalyzeRoute:
    """Tests for the log analysis route."""

    def test_analyze_nonexistent_file(self, client):
        """Test analyze route with non-existent file ID."""
        response = client.get('/analyze/99999')
        assert response.status_code == 404

    def test_analyze_valid_file(self, client, sample_log_file):
        """Test analyze route with valid file."""
        response = client.get(f'/analyze/{sample_log_file}')
        assert response.status_code == 200

    def test_analyze_parses_file(self, client, app, sample_log_file):
        """Test that analyze parses an unparsed file."""
        response = client.get(f'/analyze/{sample_log_file}')
        assert response.status_code == 200

        with app.app_context():
            log_file = LogFile.query.get(sample_log_file)
            assert log_file.parsed == True

    def test_analyze_shows_issues(self, client, parsed_log_file):
        """Test that analyze shows detected issues."""
        response = client.get(f'/analyze/{parsed_log_file}')
        assert response.status_code == 200


# =============================================================================
# Route 9: view_log (/log/<int:file_id>)
# =============================================================================
class TestViewLogRoute:
    """Tests for the log viewer route."""

    def test_view_log_nonexistent(self, client):
        """Test view_log with non-existent file."""
        response = client.get('/log/99999')
        assert response.status_code == 404

    def test_view_log_valid(self, client, parsed_log_file):
        """Test view_log with valid file."""
        response = client.get(f'/log/{parsed_log_file}')
        assert response.status_code == 200

    def test_view_log_filter_severity(self, client, parsed_log_file):
        """Test view_log with severity filter."""
        response = client.get(f'/log/{parsed_log_file}?severity=ERROR')
        assert response.status_code == 200

    def test_view_log_filter_service(self, client, parsed_log_file):
        """Test view_log with service filter."""
        response = client.get(f'/log/{parsed_log_file}?service=video-service')
        assert response.status_code == 200

    def test_view_log_pagination(self, client, parsed_log_file):
        """Test view_log pagination."""
        response = client.get(f'/log/{parsed_log_file}?page=1&per_page=50')
        assert response.status_code == 200

    def test_view_log_search(self, client, parsed_log_file):
        """Test view_log search functionality."""
        response = client.get(f'/log/{parsed_log_file}?search=camera')
        assert response.status_code == 200


# =============================================================================
# Route 10: compare (/compare)
# =============================================================================
class TestCompareRoute:
    """Tests for the log comparison route."""

    def test_compare_get(self, client):
        """Test compare page renders."""
        response = client.get('/compare')
        assert response.status_code == 200

    def test_compare_with_files(self, client, parsed_log_file):
        """Test compare page shows available files."""
        response = client.get('/compare')
        assert response.status_code == 200


# =============================================================================
# Route 11: issues_list (/issues)
# =============================================================================
class TestIssuesListRoute:
    """Tests for the issues list route."""

    def test_issues_list_empty(self, client):
        """Test issues list with no issues."""
        response = client.get('/issues')
        assert response.status_code == 200

    def test_issues_list_with_issues(self, client, parsed_log_file):
        """Test issues list with existing issues."""
        response = client.get('/issues')
        assert response.status_code == 200

    def test_issues_list_filter_severity(self, client, parsed_log_file):
        """Test issues list severity filter."""
        response = client.get('/issues?severity=ERROR')
        assert response.status_code == 200

    def test_issues_list_filter_status(self, client, parsed_log_file):
        """Test issues list status filter."""
        response = client.get('/issues?status=open')
        assert response.status_code == 200

    def test_issues_list_all_status(self, client, parsed_log_file):
        """Test issues list with all statuses."""
        response = client.get('/issues?status=all')
        assert response.status_code == 200


# =============================================================================
# Route 12: issue_detail (/issue/<int:issue_id>)
# =============================================================================
class TestIssueDetailRoute:
    """Tests for the issue detail route."""

    def test_issue_detail_nonexistent(self, client):
        """Test issue detail with non-existent issue."""
        response = client.get('/issue/99999')
        assert response.status_code == 404

    def test_issue_detail_valid(self, client, sample_issue):
        """Test issue detail with valid issue."""
        response = client.get(f'/issue/{sample_issue}')
        assert response.status_code == 200


# =============================================================================
# Route 13: create_bug_report (/bug-report/create/<int:issue_id>)
# =============================================================================
class TestCreateBugReportRoute:
    """Tests for the bug report creation route."""

    def test_create_bug_report_get_nonexistent(self, client):
        """Test create bug report GET with non-existent issue."""
        response = client.get('/bug-report/create/99999')
        assert response.status_code == 404

    def test_create_bug_report_get_valid(self, client, sample_issue):
        """Test create bug report GET with valid issue."""
        response = client.get(f'/bug-report/create/{sample_issue}')
        assert response.status_code == 200

    def test_create_bug_report_post(self, client, app, sample_issue):
        """Test creating a bug report via POST."""
        response = client.post(f'/bug-report/create/{sample_issue}', data={
            'template': 'default',
            'steps_to_reproduce': 'Test steps',
            'expected_behavior': 'Expected behavior',
            'additional_context': 'Additional context'
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/bug-report/' in response.location


# =============================================================================
# Route 14: create_jira_bug (/bug-report/jira)
# =============================================================================
class TestCreateJiraBugRoute:
    """Tests for the Jira bug creation route."""

    def test_create_jira_bug_manual_mode(self, client):
        """Test Jira bug creation in manual mode (no issue)."""
        response = client.get('/bug-report/jira')
        assert response.status_code == 200

    def test_create_jira_bug_with_issue(self, client, sample_issue):
        """Test Jira bug creation with existing issue."""
        response = client.get(f'/bug-report/jira/{sample_issue}')
        assert response.status_code == 200

    def test_create_jira_bug_with_prefill(self, client):
        """Test Jira bug creation with URL prefill parameters."""
        response = client.get('/bug-report/jira?title=Test&severity=ERROR&description=Test%20desc')
        assert response.status_code == 200

    def test_create_jira_bug_nonexistent_issue(self, client):
        """Test Jira bug creation with non-existent issue."""
        response = client.get('/bug-report/jira/99999')
        assert response.status_code == 404


# =============================================================================
# Route 15: view_bug_report (/bug-report/<int:report_id>)
# =============================================================================
class TestViewBugReportRoute:
    """Tests for the bug report view route."""

    def test_view_bug_report_nonexistent(self, client):
        """Test viewing non-existent bug report."""
        response = client.get('/bug-report/99999')
        assert response.status_code == 404

    def test_view_bug_report_valid(self, client, sample_bug_report):
        """Test viewing valid bug report."""
        response = client.get(f'/bug-report/{sample_bug_report}')
        assert response.status_code == 200


# =============================================================================
# Route 16: bug_reports_list (/bug-reports)
# =============================================================================
class TestBugReportsListRoute:
    """Tests for the bug reports list route."""

    def test_bug_reports_list_empty(self, client):
        """Test bug reports list with no reports."""
        response = client.get('/bug-reports')
        assert response.status_code == 200

    def test_bug_reports_list_with_reports(self, client, sample_bug_report):
        """Test bug reports list with existing reports."""
        response = client.get('/bug-reports')
        assert response.status_code == 200


# =============================================================================
# Route 17: export_bug_report (/bug-report/<int:report_id>/export/<format>)
# =============================================================================
class TestExportBugReportRoute:
    """Tests for the bug report export route."""

    def test_export_bug_report_nonexistent(self, client):
        """Test exporting non-existent bug report."""
        response = client.get('/bug-report/99999/export/json')
        assert response.status_code == 404

    def test_export_bug_report_json(self, client, sample_bug_report):
        """Test exporting bug report as JSON."""
        response = client.get(f'/bug-report/{sample_bug_report}/export/json')
        assert response.status_code == 200
        assert response.content_type == 'application/json'
        assert 'attachment' in response.headers['Content-Disposition']

    def test_export_bug_report_markdown(self, client, sample_bug_report):
        """Test exporting bug report as Markdown."""
        response = client.get(f'/bug-report/{sample_bug_report}/export/markdown')
        assert response.status_code == 200
        assert 'text/markdown' in response.content_type

    def test_export_bug_report_text(self, client, sample_bug_report):
        """Test exporting bug report as plain text."""
        response = client.get(f'/bug-report/{sample_bug_report}/export/text')
        assert response.status_code == 200
        assert 'text/plain' in response.content_type

    def test_export_bug_report_unknown_format(self, client, sample_bug_report):
        """Test exporting bug report with unknown format defaults to text."""
        response = client.get(f'/bug-report/{sample_bug_report}/export/unknown')
        assert response.status_code == 200
        assert 'text/plain' in response.content_type


# =============================================================================
# Route 18: charts (/charts/<int:file_id>)
# =============================================================================
class TestChartsRoute:
    """Tests for the charts visualization route."""

    def test_charts_nonexistent_file(self, client):
        """Test charts with non-existent file."""
        response = client.get('/charts/99999')
        assert response.status_code == 404

    def test_charts_valid_file(self, client, parsed_log_file):
        """Test charts with valid file."""
        response = client.get(f'/charts/{parsed_log_file}')
        assert response.status_code == 200


# =============================================================================
# Route 19: delete_log (/delete/<int:file_id>)
# =============================================================================
class TestDeleteLogRoute:
    """Tests for the log deletion route."""

    def test_delete_log_nonexistent(self, client):
        """Test deleting non-existent file."""
        response = client.post('/delete/99999')
        assert response.status_code == 404

    def test_delete_log_valid(self, client, app, sample_log_file):
        """Test deleting valid file."""
        response = client.post(f'/delete/{sample_log_file}', follow_redirects=False)
        assert response.status_code == 302

        with app.app_context():
            log_file = LogFile.query.get(sample_log_file)
            assert log_file is None

    def test_delete_log_removes_file_from_disk(self, client, app, sample_log_file):
        """Test that delete removes the file from disk."""
        with app.app_context():
            log_file = LogFile.query.get(sample_log_file)
            file_path = app.config['UPLOAD_FOLDER'] / log_file.filename
            assert file_path.exists()

        client.post(f'/delete/{sample_log_file}')

        with app.app_context():
            assert not file_path.exists()

    def test_delete_log_get_not_allowed(self, client, sample_log_file):
        """Test that GET method is not allowed for delete."""
        response = client.get(f'/delete/{sample_log_file}')
        assert response.status_code == 405


# =============================================================================
# Route 20: delete_all (/delete-all)
# =============================================================================
class TestDeleteAllRoute:
    """Tests for the delete all route."""

    def test_delete_all_empty(self, client):
        """Test delete all with no data."""
        response = client.post('/delete-all', follow_redirects=False)
        assert response.status_code == 302

    def test_delete_all_with_data(self, client, app, parsed_log_file, sample_bug_report):
        """Test delete all removes all data."""
        # Verify data exists before delete
        with app.app_context():
            assert LogFile.query.count() > 0
            assert LogEntry.query.count() > 0
            assert Issue.query.count() > 0
            assert BugReport.query.count() > 0

        response = client.post('/delete-all', follow_redirects=False)
        assert response.status_code == 302

        # Verify all data deleted
        with app.app_context():
            assert LogFile.query.count() == 0
            assert LogEntry.query.count() == 0
            assert Issue.query.count() == 0
            assert BugReport.query.count() == 0

    def test_delete_all_get_not_allowed(self, client):
        """Test that GET method is not allowed for delete-all."""
        response = client.get('/delete-all')
        assert response.status_code == 405


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================
class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_file_on_disk(self, client, app):
        """Test analyze when file exists in DB but not on disk."""
        with app.app_context():
            # Create a log file record without the physical file
            log_file = LogFile(
                filename='missing.log',
                original_filename='missing.log',
                file_size=100,
                parsed=False
            )
            db.session.add(log_file)
            db.session.commit()
            file_id = log_file.id

        response = client.get(f'/analyze/{file_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'not found' in response.data.lower()

    def test_upload_large_filename(self, client, app):
        """Test upload with very long filename."""
        long_name = 'a' * 200 + '.log'
        data = {
            'file': (BytesIO(b'test content'), long_name)
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data')
        # Should handle gracefully (truncate or reject)
        assert response.status_code in [200, 302]

    def test_paste_log_special_characters(self, client, app):
        """Test paste log with special characters in content."""
        special_content = '2024-01-01 [INFO] Unicode test: \u00e9\u00e8\u00e0 <script>alert("xss")</script>'
        response = client.post('/paste-log', data={
            'log_name': 'special_test',
            'log_content': special_content
        }, follow_redirects=True)
        assert response.status_code == 200

    def test_view_log_invalid_page(self, client, parsed_log_file):
        """Test view_log with invalid page number."""
        response = client.get(f'/log/{parsed_log_file}?page=-1')
        # Should handle gracefully
        assert response.status_code == 200

    def test_view_log_very_large_page(self, client, parsed_log_file):
        """Test view_log with very large page number."""
        response = client.get(f'/log/{parsed_log_file}?page=999999')
        # Should handle gracefully (empty results)
        assert response.status_code == 200


# =============================================================================
# Flash Messages
# =============================================================================
class TestFlashMessages:
    """Tests for flash message behavior."""

    def test_upload_success_flash(self, client, app):
        """Test success flash message on upload."""
        log_content = b"2024-01-01 10:00:00 [INFO] Test log"
        data = {
            'file': (BytesIO(log_content), 'flash_test.log')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert response.status_code == 200
        assert b'uploaded successfully' in response.data

    def test_delete_success_flash(self, client, sample_log_file):
        """Test success flash message on delete."""
        response = client.post(f'/delete/{sample_log_file}', follow_redirects=True)
        assert response.status_code == 200
        assert b'deleted successfully' in response.data

    def test_delete_all_success_flash(self, client):
        """Test success flash message on delete all."""
        response = client.post('/delete-all', follow_redirects=True)
        assert response.status_code == 200
        assert b'deleted successfully' in response.data


# =============================================================================
# Form Validation
# =============================================================================
class TestFormValidation:
    """Tests for form validation."""

    def test_paste_log_whitespace_content(self, client):
        """Test paste log with only whitespace content."""
        response = client.post('/paste-log', data={
            'log_name': 'whitespace',
            'log_content': '   \n\t   '
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'No log content provided' in response.data

    def test_camera_download_missing_ip(self, client):
        """Test camera download without IP."""
        response = client.post('/camera-download', data={
            'camera_ip': '',
            'username': 'root',
            'password': 'root',
            'port': '22'
        }, follow_redirects=True)
        # Should handle gracefully
        assert response.status_code == 200


# =============================================================================
# Redirect Behavior
# =============================================================================
class TestRedirectBehavior:
    """Tests for redirect behavior."""

    def test_upload_redirects_to_analyze(self, client):
        """Test that successful upload redirects to analyze."""
        data = {
            'file': (BytesIO(b'test content'), 'redirect_test.log')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=False)
        assert response.status_code == 302
        assert '/analyze/' in response.location

    def test_paste_log_redirects_to_analyze(self, client):
        """Test that paste log redirects to analyze."""
        response = client.post('/paste-log', data={
            'log_name': 'test',
            'log_content': 'test content'
        }, follow_redirects=False)
        assert response.status_code == 302
        assert '/analyze/' in response.location

    def test_create_bug_report_redirects_to_view(self, client, sample_issue):
        """Test that bug report creation redirects to view."""
        response = client.post(f'/bug-report/create/{sample_issue}', data={
            'template': 'default'
        }, follow_redirects=False)
        assert response.status_code == 302
        assert '/bug-report/' in response.location

    def test_delete_redirects_to_index(self, client, sample_log_file):
        """Test that delete redirects to index."""
        response = client.post(f'/delete/{sample_log_file}', follow_redirects=False)
        assert response.status_code == 302
        # Should redirect to index
        assert response.location.endswith('/') or 'main.index' in response.location


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
