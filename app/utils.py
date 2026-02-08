"""
User identity helpers for per-user data isolation.
"""
from flask import g, abort, session as flask_session
from app.models import LogFile


def get_current_user():
    """Return the current user's email from g.user_email."""
    return getattr(g, 'user_email', None)


def user_log_files():
    """Return a query for log files owned by the current user.

    Includes files with NULL user_email for backward compatibility
    when the current user is the local dev user.
    """
    from flask import current_app
    from sqlalchemy import or_

    user = get_current_user()
    local_dev = current_app.config.get('LOCAL_DEV_USER', 'local-dev@localhost')

    if user == local_dev:
        # Local dev user sees their own files AND legacy NULL-owner files
        return LogFile.query.filter(
            or_(LogFile.user_email == user, LogFile.user_email.is_(None))
        )
    return LogFile.query.filter_by(user_email=user)


def user_owns_log_file(file_id):
    """Return LogFile if owned by current user, else abort 403.

    Allows NULL user_email for backward compatibility with legacy data.
    """
    log_file = LogFile.query.get_or_404(file_id)
    user = get_current_user()

    from flask import current_app
    local_dev = current_app.config.get('LOCAL_DEV_USER', 'local-dev@localhost')

    if log_file.user_email is None and user == local_dev:
        return log_file
    if log_file.user_email == user:
        return log_file

    abort(403)


def get_user_s3_downloader():
    """Create an S3Downloader using the current user's credentials.

    Priority:
    1. Session-stored credentials (temporary)
    2. DB-persisted credentials (UserSettings)
    3. Fallback to global/environment credentials
    """
    from app.services import get_s3_downloader
    from app.services.s3_downloader import S3Downloader
    from app.models.saved_query import UserSettings

    user = get_current_user()

    # Check session credentials first
    session_creds = flask_session.get('s3_credentials')
    if session_creds and (session_creds.get('access_key') or session_creds.get('profile')):
        return S3Downloader(
            bucket=session_creds.get('bucket') or None,
            region=session_creds.get('region') or None,
            profile=session_creds.get('profile') or None,
            access_key=session_creds.get('access_key') or None,
            secret_key=session_creds.get('secret_key') or None,
        )

    # Check persisted user settings
    if user:
        settings = UserSettings.query.filter_by(user_email=user).first()
        if settings and (settings.s3_access_key or settings.s3_profile):
            return S3Downloader(
                bucket=settings.s3_bucket or None,
                region=settings.s3_region or None,
                profile=settings.s3_profile or None,
                access_key=settings.s3_access_key or None,
                secret_key=settings.s3_secret_key or None,
            )

    # Fallback to global credentials
    return get_s3_downloader()
