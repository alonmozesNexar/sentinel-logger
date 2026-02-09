"""
Configuration settings for Sentinel Logger
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()

APP_VERSION = '2.0.0'


class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    # Upload settings
    UPLOAD_FOLDER = BASE_DIR / 'uploads'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    # Allow all files - no extension restriction for maximum flexibility
    ALLOWED_EXTENSIONS = None  # None means allow all files

    # Database
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR}/qa_analyzer.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Log parsing settings
    LOG_CHUNK_SIZE = 10000  # Lines to process at a time for large files
    MAX_DISPLAY_LINES = 5000  # Max lines to display in UI at once

    # Issue detection thresholds
    ERROR_SEVERITY_LEVELS = {
        'CRITICAL': 5,
        'ERROR': 4,
        'WARNING': 3,
        'INFO': 2,
        'DEBUG': 1
    }

    # Camera connection settings
    CAMERA_DEFAULT_IP = os.environ.get('CAMERA_IP', '192.168.50.1')
    CAMERA_DEFAULT_USER = os.environ.get('CAMERA_USER', 'root')
    CAMERA_DEFAULT_PASSWORD = os.environ.get('CAMERA_PASSWORD', 'root')
    CAMERA_LOG_PATH = os.environ.get('CAMERA_LOG_PATH', '/var/log/messages')
    CAMERA_SSH_PORT = int(os.environ.get('CAMERA_SSH_PORT', 22))
    CAMERA_SSH_TIMEOUT = int(os.environ.get('CAMERA_SSH_TIMEOUT', 30))

    # User identity
    LOCAL_DEV_USER = os.environ.get('LOCAL_DEV_USER', 'local-dev@localhost')

    # S3 settings for NexarOne logs
    S3_BUCKET = os.environ.get('S3_BUCKET', 'sdk-logs-prod')
    S3_REGION = os.environ.get('S3_REGION', 'us-east-1')
    # AWS credentials (optional - can use IAM role or ~/.aws/credentials)
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False

    def __init__(self):
        import secrets as _secrets
        # Use env var if set, otherwise generate a random key per instance
        self.SECRET_KEY = os.environ.get('SECRET_KEY') or _secrets.token_hex(32)


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
