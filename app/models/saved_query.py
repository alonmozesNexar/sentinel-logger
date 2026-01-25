"""
Saved Query model for storing user's favorite analysis prompts
"""
from app import db
from datetime import datetime


class SavedQuery(db.Model):
    """User's saved analysis queries/prompts"""
    __tablename__ = 'saved_queries'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    query = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255))
    category = db.Column(db.String(50))  # e.g., 'boot', 'crash', 'network', 'custom'
    icon = db.Column(db.String(50))  # Bootstrap icon name
    is_default = db.Column(db.Boolean, default=False)  # Pre-built queries
    use_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'query': self.query,
            'description': self.description,
            'category': self.category,
            'icon': self.icon,
            'is_default': self.is_default,
            'use_count': self.use_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class LogAnnotation(db.Model):
    """Annotations/notes on specific log lines"""
    __tablename__ = 'log_annotations'

    id = db.Column(db.Integer, primary_key=True)
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    note = db.Column(db.Text, nullable=False)
    annotation_type = db.Column(db.String(20), default='note')  # note, important, question, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    log_file = db.relationship('LogFile', backref=db.backref('annotations', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (
        db.Index('idx_annotation_file_line', 'log_file_id', 'line_number'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'log_file_id': self.log_file_id,
            'line_number': self.line_number,
            'note': self.note,
            'annotation_type': self.annotation_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class SharedAnalysis(db.Model):
    """Shareable analysis links"""
    __tablename__ = 'shared_analyses'

    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.String(32), unique=True, nullable=False, index=True)  # UUID for URL
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id'), nullable=False)
    analysis_cache_id = db.Column(db.Integer, db.ForeignKey('ai_analysis_cache.id'))
    title = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime)
    view_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    log_file = db.relationship('LogFile', backref=db.backref('shared_analyses', lazy='dynamic'))
    analysis_cache = db.relationship('AIAnalysisCache', backref=db.backref('shared_links', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'share_id': self.share_id,
            'log_file_id': self.log_file_id,
            'analysis_cache_id': self.analysis_cache_id,
            'title': self.title,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'view_count': self.view_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'share_url': f'/shared/{self.share_id}'
        }

    @staticmethod
    def generate_share_id():
        import uuid
        return uuid.uuid4().hex


class JiraConfig(db.Model):
    """Jira API configuration (encrypted)"""
    __tablename__ = 'jira_config'

    id = db.Column(db.Integer, primary_key=True)
    server_url = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    api_token = db.Column(db.Text, nullable=False)  # Should be encrypted in production
    project_key = db.Column(db.String(20))
    default_issue_type = db.Column(db.String(50), default='Bug')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'server_url': self.server_url,
            'email': self.email,
            'project_key': self.project_key,
            'default_issue_type': self.default_issue_type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            # Note: API token is not included for security
        }
