"""
Database models for Sentinel Logger
"""
import json
import logging
from datetime import datetime

from app import db

# Import additional models
from app.models.saved_query import UserSettings, SavedQuery, LogAnnotation, SharedAnalysis, JiraConfig

logger = logging.getLogger(__name__)


def safe_json_loads(data, default=None, context=""):
    """
    Safely parse JSON data, returning default on failure.
    Logs errors for debugging.
    """
    if data is None:
        return default if default is not None else []
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Invalid JSON in {context}: {str(e)[:100]}")
        return default if default is not None else []


class LogFile(db.Model):
    """Represents an uploaded log file"""
    __tablename__ = 'log_files'

    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), index=True, nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_lines = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    warning_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    parsed = db.Column(db.Boolean, default=False)
    device_info = db.Column(db.Text)  # JSON string for camera/device metadata

    # Relationships
    entries = db.relationship('LogEntry', backref='log_file', lazy='dynamic',
                              cascade='all, delete-orphan')
    issues = db.relationship('Issue', backref='log_file', lazy='dynamic',
                             cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.original_filename,
            'file_size': self.file_size,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'total_lines': self.total_lines,
            'error_count': self.error_count,
            'warning_count': self.warning_count,
            'info_count': self.info_count,
            'parsed': self.parsed,
            'device_info': safe_json_loads(self.device_info, default=None, context=f"LogFile.device_info id={self.id}")
        }


class LogEntry(db.Model):
    """Individual log entry/line"""
    __tablename__ = 'log_entries'

    id = db.Column(db.Integer, primary_key=True)
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, index=True)
    severity = db.Column(db.String(20), index=True)  # CRITICAL, ERROR, WARNING, INFO, DEBUG
    service = db.Column(db.String(100), index=True)  # video-service, audio-service, etc.
    component = db.Column(db.String(100), index=True)  # front-camera, isp, encoder, etc.
    command = db.Column(db.String(100))  # Command type if applicable
    message = db.Column(db.Text)
    raw_content = db.Column(db.Text, nullable=False)

    # Index for faster searches
    __table_args__ = (
        db.Index('idx_severity_timestamp', 'severity', 'timestamp'),
        db.Index('idx_service_timestamp', 'service', 'timestamp'),
        db.Index('idx_component_timestamp', 'component', 'timestamp'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'line_number': self.line_number,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'severity': self.severity,
            'service': self.service,
            'component': self.component,
            'command': self.command,
            'message': self.message,
            'raw_content': self.raw_content
        }


class Issue(db.Model):
    """Detected issues in log files"""
    __tablename__ = 'issues'

    id = db.Column(db.Integer, primary_key=True)
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = db.Column(db.String(100))  # crash, timeout, resource, connection, etc.
    first_occurrence = db.Column(db.DateTime)
    last_occurrence = db.Column(db.DateTime)
    occurrence_count = db.Column(db.Integer, default=1)
    affected_lines = db.Column(db.Text)  # JSON array of line numbers
    context = db.Column(db.Text)  # Surrounding log context
    confidence_score = db.Column(db.Float, default=1.0)
    status = db.Column(db.String(20), default='open')  # open, acknowledged, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'log_file_id': self.log_file_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'first_occurrence': self.first_occurrence.isoformat() if self.first_occurrence else None,
            'last_occurrence': self.last_occurrence.isoformat() if self.last_occurrence else None,
            'occurrence_count': self.occurrence_count,
            'affected_lines': safe_json_loads(self.affected_lines, default=[], context=f"Issue.affected_lines id={self.id}"),
            'context': self.context,
            'confidence_score': self.confidence_score,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class BugReport(db.Model):
    """Generated bug reports"""
    __tablename__ = 'bug_reports'

    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issues.id'))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    steps_to_reproduce = db.Column(db.Text)
    expected_behavior = db.Column(db.Text)
    actual_behavior = db.Column(db.Text)
    severity = db.Column(db.String(20))
    environment = db.Column(db.Text)  # JSON with device/camera info
    log_snippets = db.Column(db.Text)  # Relevant log excerpts
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    exported = db.Column(db.Boolean, default=False)
    export_format = db.Column(db.String(20))  # jira, github, pdf, json

    issue = db.relationship('Issue', backref='bug_reports')

    def to_dict(self):
        return {
            'id': self.id,
            'issue_id': self.issue_id,
            'title': self.title,
            'description': self.description,
            'steps_to_reproduce': self.steps_to_reproduce,
            'expected_behavior': self.expected_behavior,
            'actual_behavior': self.actual_behavior,
            'severity': self.severity,
            'environment': safe_json_loads(self.environment, default=None, context=f"BugReport.environment id={self.id}"),
            'log_snippets': self.log_snippets,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'exported': self.exported,
            'export_format': self.export_format
        }


class AIAnalysisCache(db.Model):
    """Cached AI analysis results for log files"""
    __tablename__ = 'ai_analysis_cache'

    id = db.Column(db.Integer, primary_key=True)
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    query = db.Column(db.String(500), nullable=False)  # The analysis query/prompt
    query_hash = db.Column(db.String(64), index=True)  # Hash for quick lookup
    analysis_result = db.Column(db.Text, nullable=False)  # The AI analysis response
    relevant_logs = db.Column(db.Text)  # JSON of relevant log entries shown
    providers_used = db.Column(db.String(255))  # Which AI providers were used
    provider_count = db.Column(db.Integer, default=1)
    logs_analyzed = db.Column(db.Integer)  # Number of log entries analyzed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # Optional expiration for cache

    # Relationship
    log_file = db.relationship('LogFile', backref=db.backref('ai_analyses', lazy='dynamic', cascade='all, delete-orphan'))

    # Index for faster lookups and unique constraint to prevent race condition duplicates
    __table_args__ = (
        db.Index('idx_logfile_query', 'log_file_id', 'query_hash'),
        db.UniqueConstraint('log_file_id', 'query_hash', name='uq_logfile_query_hash'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'log_file_id': self.log_file_id,
            'query': self.query,
            'analysis_result': self.analysis_result,
            'relevant_logs': safe_json_loads(self.relevant_logs, default=[], context=f"AIAnalysisCache.relevant_logs id={self.id}"),
            'providers_used': self.providers_used.split(',') if self.providers_used else [],
            'provider_count': self.provider_count,
            'logs_analyzed': self.logs_analyzed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_cached': True
        }

    @staticmethod
    def generate_hash(query: str) -> str:
        """Generate a hash for the query for quick lookup."""
        import hashlib
        # Normalize the query (lowercase, strip whitespace)
        normalized = query.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()[:64]
