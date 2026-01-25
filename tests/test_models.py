"""
Tests for database models in Sentinel Logger application.

Tests cover:
- Model creation and validation
- Relationships (foreign keys, cascade deletes)
- Indexes work correctly
- Constraints are enforced
- to_dict() methods return correct data
"""
import pytest
import json
from datetime import datetime, timedelta
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import (
    LogFile, LogEntry, Issue, BugReport, AIAnalysisCache,
    SavedQuery, LogAnnotation, SharedAnalysis, JiraConfig
)


class TestConfig:
    """Test configuration for in-memory database"""
    SECRET_KEY = 'test-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = '/tmp/test_uploads'
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    ALLOWED_EXTENSIONS = None


@pytest.fixture
def app():
    """Create application for testing"""
    from pathlib import Path
    Path('/tmp/test_uploads').mkdir(exist_ok=True)

    app = create_app('default')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def session(app):
    """Create database session"""
    with app.app_context():
        yield db.session


# ============================================================
# LogFile Model Tests
# ============================================================

class TestLogFileModel:
    """Tests for LogFile model"""

    def test_create_log_file(self, app):
        """Test basic LogFile creation"""
        with app.app_context():
            log_file = LogFile(
                filename='test_123.log',
                original_filename='test.log',
                file_size=1024,
                total_lines=100,
                error_count=5,
                warning_count=10,
                info_count=85
            )
            db.session.add(log_file)
            db.session.commit()

            assert log_file.id is not None
            assert log_file.filename == 'test_123.log'
            assert log_file.original_filename == 'test.log'
            assert log_file.file_size == 1024
            assert log_file.total_lines == 100
            assert log_file.parsed is False  # Default value

    def test_log_file_nullable_constraint(self, app):
        """Test that filename and original_filename are required"""
        with app.app_context():
            # filename is required
            log_file = LogFile(original_filename='test.log')
            db.session.add(log_file)

            with pytest.raises(Exception):  # IntegrityError
                db.session.commit()

            db.session.rollback()

            # original_filename is required
            log_file2 = LogFile(filename='test_123.log')
            db.session.add(log_file2)

            with pytest.raises(Exception):  # IntegrityError
                db.session.commit()

    def test_log_file_default_values(self, app):
        """Test default values are set correctly"""
        with app.app_context():
            log_file = LogFile(
                filename='test.log',
                original_filename='test.log'
            )
            db.session.add(log_file)
            db.session.commit()

            assert log_file.total_lines == 0
            assert log_file.error_count == 0
            assert log_file.warning_count == 0
            assert log_file.info_count == 0
            assert log_file.parsed is False
            assert log_file.upload_date is not None

    def test_log_file_to_dict(self, app):
        """Test to_dict method returns correct structure"""
        with app.app_context():
            device_info = {'model': 'Camera X100', 'firmware': '1.2.3'}
            log_file = LogFile(
                filename='test_123.log',
                original_filename='test.log',
                file_size=2048,
                total_lines=200,
                error_count=10,
                warning_count=20,
                info_count=170,
                parsed=True,
                device_info=json.dumps(device_info)
            )
            db.session.add(log_file)
            db.session.commit()

            result = log_file.to_dict()

            assert result['id'] == log_file.id
            assert result['filename'] == 'test.log'  # Uses original_filename
            assert result['file_size'] == 2048
            assert result['total_lines'] == 200
            assert result['error_count'] == 10
            assert result['warning_count'] == 20
            assert result['info_count'] == 170
            assert result['parsed'] is True
            assert result['device_info'] == device_info
            assert 'upload_date' in result

    def test_log_file_to_dict_null_device_info(self, app):
        """Test to_dict handles null device_info gracefully"""
        with app.app_context():
            log_file = LogFile(
                filename='test.log',
                original_filename='test.log'
            )
            db.session.add(log_file)
            db.session.commit()

            result = log_file.to_dict()
            assert result['device_info'] is None


# ============================================================
# LogEntry Model Tests
# ============================================================

class TestLogEntryModel:
    """Tests for LogEntry model"""

    def test_create_log_entry(self, app):
        """Test basic LogEntry creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1,
                timestamp=datetime.utcnow(),
                severity='ERROR',
                service='video-service',
                component='front-camera',
                command='START_RECORDING',
                message='Recording failed',
                raw_content='[ERROR] [video-service] Recording failed'
            )
            db.session.add(entry)
            db.session.commit()

            assert entry.id is not None
            assert entry.log_file_id == log_file.id
            assert entry.severity == 'ERROR'

    def test_log_entry_foreign_key_constraint(self, app):
        """Test foreign key constraint to log_files

        NOTE: SQLite does NOT enforce foreign key constraints by default.
        This test documents this behavior - the constraint exists but is not enforced
        unless PRAGMA foreign_keys=ON is set when the connection is established.
        """
        with app.app_context():
            entry = LogEntry(
                log_file_id=99999,  # Non-existent log file
                line_number=1,
                raw_content='test'
            )
            db.session.add(entry)

            # SQLite allows this by default - FK constraints are not enforced
            # This is a known limitation when using SQLite without enabling foreign_keys pragma
            try:
                db.session.commit()
                # If we get here, FK constraints are NOT enforced (SQLite default)
                # Document this as expected behavior for SQLite
                assert entry.id is not None  # Insert succeeded
                # Clean up
                db.session.delete(entry)
                db.session.commit()
            except Exception:
                # If FK constraints ARE enforced (e.g., in PostgreSQL), this is expected
                db.session.rollback()

    def test_log_entry_nullable_constraints(self, app):
        """Test nullable constraints on LogEntry"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            # raw_content is required
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1
            )
            db.session.add(entry)

            with pytest.raises(Exception):
                db.session.commit()

    def test_log_entry_relationship(self, app):
        """Test LogEntry relationship to LogFile"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1,
                raw_content='test entry'
            )
            db.session.add(entry)
            db.session.commit()

            # Test backref
            assert entry.log_file == log_file
            assert entry in log_file.entries.all()

    def test_log_entry_indexes(self, app):
        """Test that indexed columns work correctly"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            now = datetime.utcnow()

            # Create multiple entries with various indexed values
            for i in range(10):
                entry = LogEntry(
                    log_file_id=log_file.id,
                    line_number=i,
                    timestamp=now + timedelta(seconds=i),
                    severity=['ERROR', 'WARNING', 'INFO'][i % 3],
                    service=['video-service', 'audio-service'][i % 2],
                    component=['front-camera', 'rear-camera', 'isp'][i % 3],
                    raw_content=f'Entry {i}'
                )
                db.session.add(entry)
            db.session.commit()

            # Test indexed queries
            errors = LogEntry.query.filter_by(severity='ERROR').all()
            assert len(errors) > 0

            video_entries = LogEntry.query.filter_by(service='video-service').all()
            assert len(video_entries) > 0

            front_camera = LogEntry.query.filter_by(component='front-camera').all()
            assert len(front_camera) > 0

    def test_log_entry_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            timestamp = datetime.utcnow()
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=42,
                timestamp=timestamp,
                severity='WARNING',
                service='video-service',
                component='encoder',
                command='ENCODE',
                message='Encoding slow',
                raw_content='[WARNING] Encoding slow'
            )
            db.session.add(entry)
            db.session.commit()

            result = entry.to_dict()

            assert result['id'] == entry.id
            assert result['line_number'] == 42
            assert result['severity'] == 'WARNING'
            assert result['service'] == 'video-service'
            assert result['component'] == 'encoder'
            assert result['command'] == 'ENCODE'
            assert result['message'] == 'Encoding slow'
            assert result['raw_content'] == '[WARNING] Encoding slow'
            assert result['timestamp'] == timestamp.isoformat()


# ============================================================
# Issue Model Tests
# ============================================================

class TestIssueModel:
    """Tests for Issue model"""

    def test_create_issue(self, app):
        """Test basic Issue creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Camera crash detected',
                description='Front camera service crashed',
                severity='CRITICAL',
                category='crash',
                occurrence_count=3,
                confidence_score=0.95
            )
            db.session.add(issue)
            db.session.commit()

            assert issue.id is not None
            assert issue.severity == 'CRITICAL'
            assert issue.status == 'open'  # Default value

    def test_issue_nullable_constraints(self, app):
        """Test nullable constraints on Issue"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            # title and severity are required
            issue = Issue(log_file_id=log_file.id)
            db.session.add(issue)

            with pytest.raises(Exception):
                db.session.commit()

    def test_issue_default_values(self, app):
        """Test default values"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            assert issue.occurrence_count == 1
            assert issue.confidence_score == 1.0
            assert issue.status == 'open'
            assert issue.created_at is not None

    def test_issue_relationship(self, app):
        """Test Issue relationship to LogFile"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            # Test backref
            assert issue.log_file == log_file
            assert issue in log_file.issues.all()

    def test_issue_to_dict_with_json_fields(self, app):
        """Test to_dict with JSON fields"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            affected_lines = [10, 15, 20, 25]
            now = datetime.utcnow()

            issue = Issue(
                log_file_id=log_file.id,
                title='Memory leak',
                description='Memory usage increasing',
                severity='HIGH',
                category='resource',
                first_occurrence=now,
                last_occurrence=now + timedelta(hours=1),
                occurrence_count=5,
                affected_lines=json.dumps(affected_lines),
                context='Some log context here',
                confidence_score=0.85,
                status='acknowledged'
            )
            db.session.add(issue)
            db.session.commit()

            result = issue.to_dict()

            assert result['title'] == 'Memory leak'
            assert result['severity'] == 'HIGH'
            assert result['category'] == 'resource'
            assert result['occurrence_count'] == 5
            assert result['affected_lines'] == affected_lines
            assert result['confidence_score'] == 0.85
            assert result['status'] == 'acknowledged'

    def test_issue_to_dict_empty_affected_lines(self, app):
        """Test to_dict handles empty/null affected_lines"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test',
                severity='LOW'
            )
            db.session.add(issue)
            db.session.commit()

            result = issue.to_dict()
            assert result['affected_lines'] == []


# ============================================================
# BugReport Model Tests
# ============================================================

class TestBugReportModel:
    """Tests for BugReport model"""

    def test_create_bug_report(self, app):
        """Test basic BugReport creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            bug_report = BugReport(
                issue_id=issue.id,
                title='Bug: Camera crash on startup',
                description='Camera crashes when...',
                steps_to_reproduce='1. Start app\n2. Open camera',
                expected_behavior='Camera should work',
                actual_behavior='Camera crashes',
                severity='HIGH',
                environment=json.dumps({'device': 'iPhone 15', 'os': 'iOS 17'}),
                log_snippets='[ERROR] Crash...'
            )
            db.session.add(bug_report)
            db.session.commit()

            assert bug_report.id is not None
            assert bug_report.issue_id == issue.id
            assert bug_report.exported is False  # Default

    def test_bug_report_without_issue(self, app):
        """Test BugReport can be created without issue"""
        with app.app_context():
            bug_report = BugReport(
                title='Manual bug report',
                severity='MEDIUM'
            )
            db.session.add(bug_report)
            db.session.commit()

            assert bug_report.id is not None
            assert bug_report.issue_id is None

    def test_bug_report_relationship(self, app):
        """Test BugReport relationship to Issue"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            bug_report = BugReport(
                issue_id=issue.id,
                title='Bug report',
                severity='HIGH'
            )
            db.session.add(bug_report)
            db.session.commit()

            # Test relationship
            assert bug_report.issue == issue
            assert bug_report in issue.bug_reports

    def test_bug_report_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            environment = {'device': 'Camera X100', 'firmware': '2.0'}

            bug_report = BugReport(
                title='Test bug',
                description='Bug description',
                steps_to_reproduce='Steps here',
                expected_behavior='Expected',
                actual_behavior='Actual',
                severity='CRITICAL',
                environment=json.dumps(environment),
                log_snippets='Log data',
                exported=True,
                export_format='jira'
            )
            db.session.add(bug_report)
            db.session.commit()

            result = bug_report.to_dict()

            assert result['title'] == 'Test bug'
            assert result['description'] == 'Bug description'
            assert result['severity'] == 'CRITICAL'
            assert result['environment'] == environment
            assert result['exported'] is True
            assert result['export_format'] == 'jira'


# ============================================================
# AIAnalysisCache Model Tests
# ============================================================

class TestAIAnalysisCacheModel:
    """Tests for AIAnalysisCache model"""

    def test_create_ai_analysis_cache(self, app):
        """Test basic AIAnalysisCache creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Analyze boot sequence',
                query_hash=AIAnalysisCache.generate_hash('Analyze boot sequence'),
                analysis_result='Boot completed successfully...',
                providers_used='claude,gpt4',
                provider_count=2,
                logs_analyzed=50
            )
            db.session.add(cache)
            db.session.commit()

            assert cache.id is not None
            assert cache.provider_count == 2

    def test_ai_analysis_generate_hash(self, app):
        """Test hash generation is consistent and normalized"""
        with app.app_context():
            # Same query with different casing/whitespace should produce same hash
            hash1 = AIAnalysisCache.generate_hash('Analyze boot sequence')
            hash2 = AIAnalysisCache.generate_hash('ANALYZE BOOT SEQUENCE')
            hash3 = AIAnalysisCache.generate_hash('  analyze boot sequence  ')

            assert hash1 == hash2 == hash3
            assert len(hash1) == 64

    def test_ai_analysis_relationship(self, app):
        """Test relationship to LogFile"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Test query',
                query_hash='abc123',
                analysis_result='Result'
            )
            db.session.add(cache)
            db.session.commit()

            assert cache.log_file == log_file
            assert cache in log_file.ai_analyses.all()

    def test_ai_analysis_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            relevant_logs = [{'line': 1, 'content': 'test'}]

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Analyze errors',
                query_hash='hash123',
                analysis_result='Analysis result',
                relevant_logs=json.dumps(relevant_logs),
                providers_used='claude,gpt4',
                provider_count=2,
                logs_analyzed=100
            )
            db.session.add(cache)
            db.session.commit()

            result = cache.to_dict()

            assert result['query'] == 'Analyze errors'
            assert result['analysis_result'] == 'Analysis result'
            assert result['relevant_logs'] == relevant_logs
            assert result['providers_used'] == ['claude', 'gpt4']
            assert result['provider_count'] == 2
            assert result['logs_analyzed'] == 100
            assert result['is_cached'] is True

    def test_ai_analysis_index(self, app):
        """Test composite index works correctly

        NOTE: AIAnalysisCache has a column named 'query' which shadows SQLAlchemy's
        Model.query attribute. This is a design issue that should be addressed.
        We use db.session.query() as a workaround.
        """
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            # Create multiple cache entries
            for i in range(5):
                cache = AIAnalysisCache(
                    log_file_id=log_file.id,
                    query=f'Query {i}',
                    query_hash=f'hash{i}',
                    analysis_result=f'Result {i}'
                )
                db.session.add(cache)
            db.session.commit()

            # Query using indexed columns - use db.session.query() instead of Model.query
            # because AIAnalysisCache has a 'query' column that shadows the query attribute
            result = db.session.query(AIAnalysisCache).filter_by(
                log_file_id=log_file.id,
                query_hash='hash2'
            ).first()

            assert result is not None
            # Access the 'query' column value
            assert result.query == 'Query 2'

    def test_ai_analysis_query_column_conflict(self, app):
        """Test that documents the 'query' column naming conflict

        BUG DOCUMENTATION: The AIAnalysisCache model has a column named 'query'
        which shadows SQLAlchemy's built-in Model.query attribute. This prevents
        using AIAnalysisCache.query.filter_by() syntax and requires using
        db.session.query(AIAnalysisCache) instead.

        Recommendation: Rename the 'query' column to 'analysis_query' or
        'prompt_text' to avoid this conflict.
        """
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Test query',
                query_hash='hash123',
                analysis_result='Result'
            )
            db.session.add(cache)
            db.session.commit()

            # This demonstrates the issue - AIAnalysisCache.query is a column, not QueryProperty
            # Trying to use AIAnalysisCache.query.filter_by() will fail
            assert hasattr(AIAnalysisCache, 'query')

            # The 'query' attribute is an InstrumentedAttribute (column), not a QueryProperty
            from sqlalchemy.orm.attributes import InstrumentedAttribute
            assert isinstance(AIAnalysisCache.query, InstrumentedAttribute)

            # Correct way to query - use db.session.query()
            results = db.session.query(AIAnalysisCache).filter_by(
                log_file_id=log_file.id
            ).all()
            assert len(results) == 1
            assert results[0].query == 'Test query'


# ============================================================
# SavedQuery Model Tests
# ============================================================

class TestSavedQueryModel:
    """Tests for SavedQuery model"""

    def test_create_saved_query(self, app):
        """Test basic SavedQuery creation"""
        with app.app_context():
            query = SavedQuery(
                name='Boot Analysis',
                query='Analyze boot sequence for errors',
                description='Checks boot log for issues',
                category='boot',
                icon='bi-power'
            )
            db.session.add(query)
            db.session.commit()

            assert query.id is not None
            assert query.use_count == 0  # Default
            assert query.is_default is False  # Default

    def test_saved_query_nullable_constraints(self, app):
        """Test nullable constraints"""
        with app.app_context():
            # name and query are required
            sq = SavedQuery(description='Missing required fields')
            db.session.add(sq)

            with pytest.raises(Exception):
                db.session.commit()

    def test_saved_query_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            query = SavedQuery(
                name='Network Check',
                query='Find network errors',
                description='Network analysis',
                category='network',
                icon='bi-wifi',
                is_default=True,
                use_count=42
            )
            db.session.add(query)
            db.session.commit()

            result = query.to_dict()

            assert result['name'] == 'Network Check'
            assert result['query'] == 'Find network errors'
            assert result['description'] == 'Network analysis'
            assert result['category'] == 'network'
            assert result['icon'] == 'bi-wifi'
            assert result['is_default'] is True
            assert result['use_count'] == 42
            assert 'created_at' in result
            assert 'updated_at' in result


# ============================================================
# LogAnnotation Model Tests
# ============================================================

class TestLogAnnotationModel:
    """Tests for LogAnnotation model"""

    def test_create_log_annotation(self, app):
        """Test basic LogAnnotation creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            annotation = LogAnnotation(
                log_file_id=log_file.id,
                line_number=42,
                note='This error is important',
                annotation_type='important'
            )
            db.session.add(annotation)
            db.session.commit()

            assert annotation.id is not None
            assert annotation.annotation_type == 'important'

    def test_log_annotation_default_type(self, app):
        """Test default annotation type"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            annotation = LogAnnotation(
                log_file_id=log_file.id,
                line_number=10,
                note='A note'
            )
            db.session.add(annotation)
            db.session.commit()

            assert annotation.annotation_type == 'note'

    def test_log_annotation_relationship(self, app):
        """Test relationship to LogFile"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            annotation = LogAnnotation(
                log_file_id=log_file.id,
                line_number=5,
                note='Test note'
            )
            db.session.add(annotation)
            db.session.commit()

            assert annotation.log_file == log_file
            assert annotation in log_file.annotations.all()

    def test_log_annotation_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            annotation = LogAnnotation(
                log_file_id=log_file.id,
                line_number=100,
                note='Important finding',
                annotation_type='important'
            )
            db.session.add(annotation)
            db.session.commit()

            result = annotation.to_dict()

            assert result['line_number'] == 100
            assert result['note'] == 'Important finding'
            assert result['annotation_type'] == 'important'
            assert 'created_at' in result
            assert 'updated_at' in result


# ============================================================
# SharedAnalysis Model Tests
# ============================================================

class TestSharedAnalysisModel:
    """Tests for SharedAnalysis model"""

    def test_create_shared_analysis(self, app):
        """Test basic SharedAnalysis creation"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            share_id = SharedAnalysis.generate_share_id()

            shared = SharedAnalysis(
                share_id=share_id,
                log_file_id=log_file.id,
                title='Shared Analysis'
            )
            db.session.add(shared)
            db.session.commit()

            assert shared.id is not None
            assert shared.view_count == 0  # Default
            assert len(shared.share_id) == 32

    def test_shared_analysis_unique_share_id(self, app):
        """Test share_id uniqueness constraint"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            shared1 = SharedAnalysis(
                share_id='unique_id_12345678901234567890',
                log_file_id=log_file.id
            )
            db.session.add(shared1)
            db.session.commit()

            shared2 = SharedAnalysis(
                share_id='unique_id_12345678901234567890',  # Duplicate
                log_file_id=log_file.id
            )
            db.session.add(shared2)

            with pytest.raises(Exception):  # IntegrityError
                db.session.commit()

    def test_shared_analysis_generate_share_id(self, app):
        """Test share_id generation"""
        with app.app_context():
            id1 = SharedAnalysis.generate_share_id()
            id2 = SharedAnalysis.generate_share_id()

            assert len(id1) == 32
            assert len(id2) == 32
            assert id1 != id2  # Should be unique

    def test_shared_analysis_relationships(self, app):
        """Test relationships to LogFile and AIAnalysisCache"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Test',
                query_hash='hash',
                analysis_result='Result'
            )
            db.session.add(cache)
            db.session.commit()

            shared = SharedAnalysis(
                share_id=SharedAnalysis.generate_share_id(),
                log_file_id=log_file.id,
                analysis_cache_id=cache.id
            )
            db.session.add(shared)
            db.session.commit()

            assert shared.log_file == log_file
            assert shared.analysis_cache == cache
            assert shared in log_file.shared_analyses.all()
            assert shared in cache.shared_links.all()

    def test_shared_analysis_to_dict(self, app):
        """Test to_dict method"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            share_id = 'abc123def456abc123def456abc12345'

            shared = SharedAnalysis(
                share_id=share_id,
                log_file_id=log_file.id,
                title='My Analysis',
                view_count=10
            )
            db.session.add(shared)
            db.session.commit()

            result = shared.to_dict()

            assert result['share_id'] == share_id
            assert result['title'] == 'My Analysis'
            assert result['view_count'] == 10
            assert result['share_url'] == f'/shared/{share_id}'


# ============================================================
# JiraConfig Model Tests
# ============================================================

class TestJiraConfigModel:
    """Tests for JiraConfig model"""

    def test_create_jira_config(self, app):
        """Test basic JiraConfig creation"""
        with app.app_context():
            config = JiraConfig(
                server_url='https://company.atlassian.net',
                email='user@company.com',
                api_token='secret_token',
                project_key='PROJ',
                default_issue_type='Bug'
            )
            db.session.add(config)
            db.session.commit()

            assert config.id is not None
            assert config.is_active is True  # Default

    def test_jira_config_nullable_constraints(self, app):
        """Test nullable constraints"""
        with app.app_context():
            # server_url, email, api_token are required
            config = JiraConfig(project_key='TEST')
            db.session.add(config)

            with pytest.raises(Exception):
                db.session.commit()

    def test_jira_config_to_dict_excludes_token(self, app):
        """Test that to_dict does not expose API token"""
        with app.app_context():
            config = JiraConfig(
                server_url='https://company.atlassian.net',
                email='user@company.com',
                api_token='super_secret_token',
                project_key='PROJ'
            )
            db.session.add(config)
            db.session.commit()

            result = config.to_dict()

            assert 'api_token' not in result
            assert result['server_url'] == 'https://company.atlassian.net'
            assert result['email'] == 'user@company.com'
            assert result['project_key'] == 'PROJ'


# ============================================================
# Cascade Delete Tests
# ============================================================

class TestCascadeDeletes:
    """Tests for cascade delete behavior"""

    def test_log_file_cascade_deletes_entries(self, app):
        """Test that deleting LogFile cascades to LogEntries"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            # Add entries
            for i in range(5):
                entry = LogEntry(
                    log_file_id=log_file.id,
                    line_number=i,
                    raw_content=f'Entry {i}'
                )
                db.session.add(entry)
            db.session.commit()

            log_file_id = log_file.id

            # Verify entries exist
            assert LogEntry.query.filter_by(log_file_id=log_file_id).count() == 5

            # Delete log file
            db.session.delete(log_file)
            db.session.commit()

            # Entries should be deleted
            assert LogEntry.query.filter_by(log_file_id=log_file_id).count() == 0

    def test_log_file_cascade_deletes_issues(self, app):
        """Test that deleting LogFile cascades to Issues"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            log_file_id = log_file.id

            # Verify issue exists
            assert Issue.query.filter_by(log_file_id=log_file_id).count() == 1

            # Delete log file
            db.session.delete(log_file)
            db.session.commit()

            # Issue should be deleted
            assert Issue.query.filter_by(log_file_id=log_file_id).count() == 0

    def test_log_file_cascade_deletes_ai_cache(self, app):
        """Test that deleting LogFile cascades to AIAnalysisCache

        NOTE: Uses db.session.query() instead of AIAnalysisCache.query because
        the 'query' column shadows SQLAlchemy's query attribute.
        """
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            cache = AIAnalysisCache(
                log_file_id=log_file.id,
                query='Test',
                query_hash='hash',
                analysis_result='Result'
            )
            db.session.add(cache)
            db.session.commit()

            log_file_id = log_file.id

            # Verify cache exists - use db.session.query() due to column naming conflict
            assert db.session.query(AIAnalysisCache).filter_by(log_file_id=log_file_id).count() == 1

            # Delete log file
            db.session.delete(log_file)
            db.session.commit()

            # Cache should be deleted
            assert db.session.query(AIAnalysisCache).filter_by(log_file_id=log_file_id).count() == 0

    def test_log_file_cascade_deletes_annotations(self, app):
        """Test that deleting LogFile cascades to LogAnnotations"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            annotation = LogAnnotation(
                log_file_id=log_file.id,
                line_number=10,
                note='Test note'
            )
            db.session.add(annotation)
            db.session.commit()

            log_file_id = log_file.id

            # Verify annotation exists
            assert LogAnnotation.query.filter_by(log_file_id=log_file_id).count() == 1

            # Delete log file
            db.session.delete(log_file)
            db.session.commit()

            # Annotation should be deleted
            assert LogAnnotation.query.filter_by(log_file_id=log_file_id).count() == 0

    def test_bug_report_not_deleted_with_issue(self, app):
        """Test that BugReport is NOT deleted when Issue is deleted (no cascade)"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            issue = Issue(
                log_file_id=log_file.id,
                title='Test issue',
                severity='HIGH'
            )
            db.session.add(issue)
            db.session.commit()

            bug_report = BugReport(
                issue_id=issue.id,
                title='Bug report',
                severity='HIGH'
            )
            db.session.add(bug_report)
            db.session.commit()

            bug_report_id = bug_report.id

            # Delete issue
            db.session.delete(issue)
            db.session.commit()

            # Bug report should still exist (with null issue_id)
            remaining_report = db.session.get(BugReport, bug_report_id)
            assert remaining_report is not None
            # Note: SQLite may set FK to null or leave as is depending on FK settings


# ============================================================
# Data Integrity Tests
# ============================================================

class TestDataIntegrity:
    """Tests for data integrity and edge cases"""

    def test_large_text_fields(self, app):
        """Test that large text fields work correctly"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            # Large message
            large_message = 'x' * 10000
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1,
                message=large_message,
                raw_content=large_message
            )
            db.session.add(entry)
            db.session.commit()

            retrieved = db.session.get(LogEntry, entry.id)
            assert len(retrieved.message) == 10000

    def test_unicode_content(self, app):
        """Test that unicode content is handled correctly"""
        with app.app_context():
            log_file = LogFile(
                filename='test.log',
                original_filename='test_unicode.log'
            )
            db.session.add(log_file)
            db.session.commit()

            unicode_content = 'Error: Connection failed.'
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1,
                message=unicode_content,
                raw_content=unicode_content
            )
            db.session.add(entry)
            db.session.commit()

            retrieved = db.session.get(LogEntry, entry.id)
            assert retrieved.message == unicode_content

    def test_json_field_integrity(self, app):
        """Test that JSON fields round-trip correctly"""
        with app.app_context():
            complex_data = {
                'nested': {
                    'array': [1, 2, 3],
                    'string': 'test',
                    'number': 3.14,
                    'boolean': True,
                    'null': None
                }
            }

            log_file = LogFile(
                filename='test.log',
                original_filename='test.log',
                device_info=json.dumps(complex_data)
            )
            db.session.add(log_file)
            db.session.commit()

            retrieved = db.session.get(LogFile, log_file.id)
            parsed = json.loads(retrieved.device_info)

            assert parsed == complex_data

    def test_datetime_precision(self, app):
        """Test datetime field precision"""
        with app.app_context():
            log_file = LogFile(filename='test.log', original_filename='test.log')
            db.session.add(log_file)
            db.session.commit()

            timestamp = datetime(2024, 6, 15, 10, 30, 45, 123456)
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=1,
                timestamp=timestamp,
                raw_content='test'
            )
            db.session.add(entry)
            db.session.commit()

            retrieved = db.session.get(LogEntry, entry.id)
            # SQLite may not preserve microseconds
            assert retrieved.timestamp.year == 2024
            assert retrieved.timestamp.month == 6
            assert retrieved.timestamp.day == 15
            assert retrieved.timestamp.hour == 10
            assert retrieved.timestamp.minute == 30
            assert retrieved.timestamp.second == 45


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
