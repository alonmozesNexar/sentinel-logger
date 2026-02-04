#!/usr/bin/env python3
"""
Sentinel Logger - Main Entry Point

A web application for analyzing camera/hardware log files.
Automatically detects errors, warnings, and issues, and helps QA testers
create bug reports efficiently.

Usage:
    python main.py [--host HOST] [--port PORT] [--debug]

Example:
    python main.py --host 0.0.0.0 --port 5000 --debug
"""

import argparse
import os
import sys
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
        description='Sentinel Logger - Web Application'
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
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    # Create the Flask application
    app = create_app(args.config)

    # Check AI Agent status (supports multiple providers)
    ai_keys = ['GROQ_API_KEY', 'GOOGLE_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY']
    ai_available = any(os.environ.get(key) for key in ai_keys)
    ai_status = "ENABLED" if ai_available else "DISABLED (set GROQ_API_KEY or other AI key)"

    # Print startup info
    print(f"""
    ============================================
    Sentinel Logger
    ============================================
    Host: {args.host}
    Port: {args.port}
    Debug: {args.debug}
    Config: {args.config}
    AI Agent: {ai_status}

    Open your browser at: http://{args.host}:{args.port}
    ============================================
    """)

    # Run the application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug or args.config == 'development'
    )


if __name__ == '__main__':
    main()
