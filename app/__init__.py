"""
Sentinel Logger - Flask Application Factory
"""
import json
import logging
import click
from flask import Flask, render_template, g, request
from flask_sqlalchemy import SQLAlchemy
from config import config

db = SQLAlchemy()
logger = logging.getLogger(__name__)


def create_app(config_name='default'):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure upload folder exists
    app.config['UPLOAD_FOLDER'].mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register custom Jinja2 filters
    @app.template_filter('from_json')
    def from_json_filter(value):
        """Parse a JSON string into a Python object"""
        if value is None:
            return {}
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}

    # User identity middleware
    @app.before_request
    def set_user_identity():
        """Extract user email from Google IAP header or fallback to local dev user."""
        iap_header = request.headers.get('X-Goog-Authenticated-User-Email', '')
        if iap_header:
            # Strip 'accounts.google.com:' prefix
            g.user_email = iap_header.replace('accounts.google.com:', '')
        else:
            g.user_email = app.config.get('LOCAL_DEV_USER', 'local-dev@localhost')

    # Make user_email and app version available in all templates
    @app.context_processor
    def inject_globals():
        from config import APP_VERSION
        return dict(
            current_user_email=getattr(g, 'user_email', None),
            app_version=APP_VERSION,
        )

    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        """Add security headers to all responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com fonts.googleapis.com; "
            "font-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors."""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        logger.error(f"Internal server error: {error}")
        db.session.rollback()  # Rollback any failed transactions
        return render_template('errors/500.html'), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        """Handle 403 errors."""
        return render_template('errors/403.html'), 403

    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Handle file too large errors."""
        return render_template('errors/413.html'), 413

    # Register blueprints
    from app.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    # Create database tables and run migrations
    with app.app_context():
        db.create_all()
        _migrate_add_user_email(app)

    # CLI command to assign unowned records to a user
    @app.cli.command('assign-user')
    @click.argument('email')
    def assign_user_command(email):
        """Bulk-assign all records with NULL user_email to the given email."""
        from app.models import LogFile, SavedQuery, LogAnnotation, SharedAnalysis, JiraConfig
        counts = {}
        for model in [LogFile, SavedQuery, LogAnnotation, SharedAnalysis, JiraConfig]:
            count = model.query.filter_by(user_email=None).update({'user_email': email})
            counts[model.__tablename__] = count
        db.session.commit()
        total = sum(counts.values())
        click.echo(f'Assigned {total} records to {email}: {counts}')

    return app


def _migrate_add_user_email(app):
    """Add user_email column to existing tables if missing (SQLite compat)."""
    tables_to_migrate = ['log_files', 'saved_queries', 'log_annotations', 'shared_analyses', 'jira_config']
    with db.engine.connect() as conn:
        for table in tables_to_migrate:
            try:
                # Check if column already exists
                result = conn.execute(db.text(f"PRAGMA table_info({table})"))
                columns = [row[1] for row in result]
                if 'user_email' not in columns:
                    conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN user_email VARCHAR(255)"))
                    conn.execute(db.text(f"CREATE INDEX IF NOT EXISTS idx_{table}_user_email ON {table}(user_email)"))
                    conn.commit()
                    logger.info(f"Added user_email column to {table}")
            except Exception as e:
                logger.debug(f"Migration check for {table}: {e}")
