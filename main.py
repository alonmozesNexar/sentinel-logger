#!/usr/bin/env python3
"""
Sentinel Logger - Main Entry Point

A web application for analyzing camera/hardware log files.
Automatically detects errors, warnings, and issues, and helps QA testers
create bug reports efficiently.

Usage:
    sentinel-logger                        # installed via pip
    python main.py [--host HOST] [--port PORT] [--debug]

Example:
    sentinel-logger --port 5000
    python main.py --host 0.0.0.0 --port 5000 --debug
"""

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from app import create_app


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Sentinel Logger - Log debugging tool for QA testers'
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=9898,
        help='Port to listen on (default: 9898)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run in debug mode'
    )
    parser.add_argument(
        '--config',
        default='development',
        choices=['development', 'production'],
        help='Configuration to use (default: development)'
    )
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Do not auto-open browser on startup'
    )
    parser.add_argument(
        '--no-update-check',
        action='store_true',
        help='Skip checking for updates on startup'
    )
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    # Create the Flask application
    app = create_app(args.config)

    from config import APP_VERSION

    # Check AI Agent status
    ai_keys = ['GROQ_API_KEY', 'GOOGLE_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY']
    ai_available = any(os.environ.get(key) for key in ai_keys)
    ai_status = "ENABLED" if ai_available else "DISABLED (set ANTHROPIC_API_KEY or other AI key)"

    # Check S3 status (quick, non-blocking)
    s3_status = "checking..."
    try:
        from app.services.s3_downloader import S3Downloader
        s3 = S3Downloader()
        if s3.profile:
            s3_status = f"profile: {s3.profile}"
        elif s3._init_error:
            s3_status = "not configured"
        else:
            s3_status = "default credentials"
    except Exception:
        s3_status = "not configured"

    url = f"http://{args.host}:{args.port}"

    # Print startup banner
    print(f"""
    ============================================
    Sentinel Logger v{APP_VERSION}
    ============================================
    Open:   {url}
    S3:     {s3_status}
    AI:     {ai_status}
    ============================================
    """)

    # Background version check
    if not args.no_update_check:
        try:
            from app.services.version_checker import check_for_updates
            check_for_updates(APP_VERSION)
        except Exception:
            pass

    # Auto-open browser (with delay so server starts first)
    if not args.no_browser and not os.environ.get('WERKZEUG_RUN_MAIN'):
        # Only open on the initial process, not the reloader child
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    # Run the application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug or args.config == 'development'
    )


if __name__ == '__main__':
    main()
