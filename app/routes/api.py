"""
API routes - RESTful API endpoints for the web UI
"""
from flask import request, jsonify, current_app
from pathlib import Path
from datetime import datetime
import json

from app.routes import api_bp
from app import db
from app.models import LogFile, LogEntry, Issue, BugReport, AIAnalysisCache, SavedQuery, LogAnnotation, SharedAnalysis, JiraConfig
from app.services import LogParser, IssueDetector, BugReportGenerator, AnalyticsService

# Try to import psutil for system monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@api_bp.route('/log-files', methods=['GET'])
def get_log_files():
    """Get all log files"""
    log_files = LogFile.query.order_by(LogFile.upload_date.desc()).all()
    return jsonify([f.to_dict() for f in log_files])


@api_bp.route('/log-files/<int:file_id>', methods=['GET'])
def get_log_file(file_id):
    """Get a specific log file"""
    log_file = LogFile.query.get_or_404(file_id)
    return jsonify(log_file.to_dict())


@api_bp.route('/log-files/<int:file_id>/entries', methods=['GET'])
def get_log_entries(file_id):
    """Get log entries with filtering and pagination"""
    log_file = LogFile.query.get_or_404(file_id)

    # Pagination with proper validation
    page = max(1, request.args.get('page', 1, type=int))
    per_page = request.args.get('per_page', 100, type=int)
    per_page = max(1, min(per_page, 500))  # Enforce range: 1-500

    # Filters
    severity = request.args.get('severity')
    service = request.args.get('service')
    search = request.args.get('search', '')
    start_line = request.args.get('start_line', type=int)
    end_line = request.args.get('end_line', type=int)

    # Build query
    query = LogEntry.query.filter_by(log_file_id=file_id)

    if severity:
        query = query.filter_by(severity=severity)
    if service:
        query = query.filter_by(service=service)
    if search:
        query = query.filter(LogEntry.raw_content.ilike(f'%{search}%'))
    if start_line:
        query = query.filter(LogEntry.line_number >= start_line)
    if end_line:
        query = query.filter(LogEntry.line_number <= end_line)

    # Paginate
    entries = query.order_by(LogEntry.line_number).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'entries': [e.to_dict() for e in entries.items],
        'total': entries.total,
        'pages': entries.pages,
        'current_page': entries.page,
        'per_page': per_page,
        'has_next': entries.has_next,
        'has_prev': entries.has_prev
    })


@api_bp.route('/log-files/<int:file_id>/issues', methods=['GET'])
def get_log_issues(file_id):
    """Get issues for a specific log file"""
    log_file = LogFile.query.get_or_404(file_id)
    issues = Issue.query.filter_by(log_file_id=file_id).all()
    return jsonify([i.to_dict() for i in issues])


@api_bp.route('/log-files/<int:file_id>/search', methods=['GET'])
def search_log_entries(file_id):
    """Search all log entries and return matching line numbers for minimap"""
    import re

    log_file = LogFile.query.get_or_404(file_id)

    query_str = request.args.get('q', '').strip()
    mode = request.args.get('mode', 'contains')

    if not query_str:
        return jsonify({'matches': [], 'total': 0})

    # Build query based on mode
    query = LogEntry.query.filter_by(log_file_id=file_id)

    if mode == 'exact':
        query = query.filter(LogEntry.raw_content.contains(query_str))
    elif mode == 'regex':
        # For regex, we need to fetch and filter in Python (SQLite doesn't support regex well)
        try:
            pattern = re.compile(query_str, re.IGNORECASE)
            all_entries = LogEntry.query.filter_by(log_file_id=file_id).all()
            matches = [e.line_number for e in all_entries if pattern.search(e.raw_content or '')]
            return jsonify({
                'matches': matches[:1000],  # Limit to 1000 for performance
                'total': len(matches)
            })
        except re.error:
            return jsonify({'matches': [], 'total': 0, 'error': 'Invalid regex'})
    else:
        # Case-insensitive contains (default)
        query = query.filter(LogEntry.raw_content.ilike(f'%{query_str}%'))

    # Get only line numbers for efficiency
    results = query.with_entities(LogEntry.line_number).order_by(LogEntry.line_number).limit(1000).all()
    matches = [r[0] for r in results]

    return jsonify({
        'matches': matches,
        'total': len(matches)
    })


@api_bp.route('/log-files/<int:file_id>/charts', methods=['GET'])
def get_chart_data(file_id):
    """Get chart data for a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    # Get entries
    entries = LogEntry.query.filter_by(log_file_id=file_id).all()
    entries_data = [e.to_dict() for e in entries]

    # Get issues
    issues = Issue.query.filter_by(log_file_id=file_id).all()
    issues_data = [i.to_dict() for i in issues]

    # Generate chart data
    analytics = AnalyticsService()
    chart_data = analytics.get_all_charts(entries_data, issues_data)

    return jsonify(chart_data)


@api_bp.route('/log-files/<int:file_id>/stats', methods=['GET'])
def get_log_stats(file_id):
    """Get statistics for a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    entries = LogEntry.query.filter_by(log_file_id=file_id).all()
    entries_data = [e.to_dict() for e in entries]

    issues = Issue.query.filter_by(log_file_id=file_id).all()
    issues_data = [i.to_dict() for i in issues]

    analytics = AnalyticsService()
    summary = analytics.get_dashboard_summary(entries_data, issues_data)

    return jsonify(summary)


@api_bp.route('/log-files/<int:file_id>/minimap', methods=['GET'])
def get_log_minimap(file_id):
    """Get minimap data for log visualization - returns severity info for each significant line"""
    log_file = LogFile.query.get_or_404(file_id)

    # Get entries with severity (errors, warnings, critical)
    entries = LogEntry.query.filter(
        LogEntry.log_file_id == file_id,
        LogEntry.severity.in_(['ERROR', 'CRITICAL', 'WARNING', 'INFO'])
    ).order_by(LogEntry.line_number).all()

    # Return line number and severity for minimap rendering
    minimap_entries = []
    for entry in entries:
        minimap_entries.append({
            'line': entry.line_number,
            'severity': entry.severity
        })

    return jsonify({
        'total_lines': log_file.total_lines,
        'error_count': log_file.error_count,
        'warning_count': log_file.warning_count,
        'entries': minimap_entries
    })


@api_bp.route('/issues', methods=['GET'])
def get_all_issues():
    """Get all issues across all log files"""
    severity = request.args.get('severity')
    status = request.args.get('status')
    category = request.args.get('category')

    query = Issue.query

    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if category:
        query = query.filter_by(category=category)

    issues = query.order_by(Issue.created_at.desc()).all()
    return jsonify([i.to_dict() for i in issues])


@api_bp.route('/issues/<int:issue_id>', methods=['GET'])
def get_issue(issue_id):
    """Get a specific issue"""
    issue = Issue.query.get_or_404(issue_id)
    return jsonify(issue.to_dict())


@api_bp.route('/issues/<int:issue_id>', methods=['PATCH'])
def update_issue(issue_id):
    """Update issue status"""
    issue = Issue.query.get_or_404(issue_id)
    data = request.get_json()

    if 'status' in data:
        issue.status = data['status']

    db.session.commit()
    return jsonify(issue.to_dict())


@api_bp.route('/issues/<int:issue_id>/context', methods=['GET'])
def get_issue_context(issue_id):
    """Get surrounding log context for an issue"""
    issue = Issue.query.get_or_404(issue_id)

    affected_lines = json.loads(issue.affected_lines) if issue.affected_lines else []
    context_before = request.args.get('before', 5, type=int)
    context_after = request.args.get('after', 5, type=int)

    context_entries = []
    if affected_lines:
        first_line = min(affected_lines)
        last_line = max(affected_lines)
        entries = LogEntry.query.filter(
            LogEntry.log_file_id == issue.log_file_id,
            LogEntry.line_number >= first_line - context_before,
            LogEntry.line_number <= last_line + context_after
        ).order_by(LogEntry.line_number).all()
        context_entries = [e.to_dict() for e in entries]

    return jsonify({
        'issue': issue.to_dict(),
        'context_entries': context_entries,
        'affected_lines': affected_lines
    })


@api_bp.route('/bug-reports', methods=['GET'])
def get_bug_reports():
    """Get all bug reports"""
    reports = BugReport.query.order_by(BugReport.created_at.desc()).all()
    return jsonify([r.to_dict() for r in reports])


@api_bp.route('/bug-reports/<int:report_id>', methods=['GET'])
def get_bug_report(report_id):
    """Get a specific bug report"""
    report = BugReport.query.get_or_404(report_id)
    return jsonify(report.to_dict())


@api_bp.route('/bug-reports', methods=['POST'])
def create_bug_report():
    """Create a new bug report"""
    data = request.get_json()

    issue_id = data.get('issue_id')
    if issue_id:
        issue = Issue.query.get_or_404(issue_id)
        log_file = issue.log_file
        device_info = json.loads(log_file.device_info) if log_file.device_info else {}

        generator = BugReportGenerator()
        report_data = generator.generate_report(
            issue.to_dict(),
            device_info=device_info,
            template_name=data.get('template', 'default'),
            additional_context=data.get('additional_context')
        )
    else:
        report_data = data

    bug_report = BugReport(
        issue_id=issue_id,
        title=data.get('title', report_data.get('title', 'Bug Report')),
        description=data.get('description', report_data.get('description', '')),
        steps_to_reproduce=data.get('steps_to_reproduce', ''),
        expected_behavior=data.get('expected_behavior', ''),
        actual_behavior=data.get('actual_behavior', report_data.get('actual_behavior', '')),
        severity=data.get('severity', report_data.get('severity')),
        environment=data.get('environment', report_data.get('environment', '{}')),
        log_snippets=data.get('log_snippets', report_data.get('log_snippets', ''))
    )
    db.session.add(bug_report)
    db.session.commit()

    return jsonify(bug_report.to_dict()), 201


# Smart search keyword mappings for camera/embedded systems
SEARCH_KEYWORDS = {
    # OTA / Firmware Updates
    'ota': ['ota', 'upgrade', 'firmware', 'update', 'flash', 'fwupdate', 'software update', 'downloading firmware'],
    'upgrade': ['ota', 'upgrade', 'firmware', 'update', 'flash', 'fwupdate'],
    'firmware': ['firmware', 'fw', 'flash', 'ota', 'update'],

    # Boot / Startup
    'boot': ['boot', 'startup', 'init', 'reboot', 'power on', 'starting', 'bootloader', 'kernel'],
    'startup': ['boot', 'startup', 'init', 'starting', 'initialization'],
    'reboot': ['reboot', 'restart', 'reset', 'power cycle'],

    # Crash / Errors
    'crash': ['crash', 'panic', 'segfault', 'killed', 'fatal', 'abort', 'exception', 'core dump', 'segmentation fault'],
    'panic': ['panic', 'kernel panic', 'crash', 'fatal'],
    'error': ['error', 'err', 'fail', 'failed', 'failure'],

    # Memory
    'memory': ['memory', 'mem', 'oom', 'out of memory', 'malloc', 'alloc', 'heap', 'ram', 'low memory'],
    'oom': ['oom', 'out of memory', 'memory', 'killed', 'cannot allocate'],

    # Storage / SD Card
    'storage': ['storage', 'sd', 'sdcard', 'disk', 'mount', 'unmount', 'filesystem', 'fs', 'mmc', 'emmc'],
    'sd': ['sd', 'sdcard', 'sd card', 'mmc', 'storage', 'mount'],
    'disk': ['disk', 'storage', 'mount', 'filesystem', 'io error', 'read error', 'write error'],

    # Network / WiFi
    'network': ['network', 'wifi', 'wlan', 'ethernet', 'connection', 'disconnect', 'ip', 'dhcp', 'socket'],
    'wifi': ['wifi', 'wlan', 'wireless', 'ssid', 'connection', 'signal'],
    'connection': ['connection', 'connect', 'disconnect', 'timeout', 'refused', 'network'],

    # Camera specific
    'camera': ['camera', 'cam', 'video', 'capture', 'sensor', 'isp', 'lens', 'road-facing', 'interior', 'facing'],
    'video': ['video', 'stream', 'recording', 'capture', 'frame', 'fps', 'encoder', 'h264', 'h265'],
    'recording': ['recording', 'record', 'capture', 'video', 'storage', 'clip'],

    # Collision / Events
    'collision': ['collision', 'impact', 'crash', 'accident', 'gsensor', 'g-sensor', 'accelerometer', 'event'],
    'event': ['event', 'trigger', 'alert', 'notification', 'collision', 'impact'],

    # Services
    'service': ['service', 'daemon', 'process', 'started', 'stopped', 'failed', 'restart'],
    'timeout': ['timeout', 'timed out', 'no response', 'hung', 'stuck', 'watchdog'],

    # Temperature
    'temperature': ['temperature', 'temp', 'thermal', 'overheat', 'cooling', 'hot', 'throttle'],
    'thermal': ['thermal', 'temperature', 'overheat', 'throttle', 'cooling'],

    # Power
    'power': ['power', 'battery', 'voltage', 'charging', 'shutdown', 'low power', 'pmic'],
    'battery': ['battery', 'power', 'voltage', 'charging', 'low battery'],

    # GPS
    'gps': ['gps', 'gnss', 'location', 'satellite', 'fix', 'coordinates', 'nmea'],
    'location': ['location', 'gps', 'position', 'coordinates'],
}


def expand_search_query(query_text):
    """Expand search query using keyword mappings"""
    query_lower = query_text.lower().strip()

    # Check if query matches any keyword category
    expanded_terms = set()

    # First, add the original query
    expanded_terms.add(query_text)

    # Check each word in the query
    words = query_lower.replace('(', ' ').replace(')', ' ').split()
    for word in words:
        word = word.strip()
        if word in SEARCH_KEYWORDS:
            expanded_terms.update(SEARCH_KEYWORDS[word])

    # Also check the full query
    if query_lower in SEARCH_KEYWORDS:
        expanded_terms.update(SEARCH_KEYWORDS[query_lower])

    return list(expanded_terms)


@api_bp.route('/search', methods=['GET'])
def search_logs():
    """Search across all log entries with smart keyword expansion"""
    query_text = request.args.get('q', '')
    severity = request.args.get('severity')
    service = request.args.get('service')
    file_id = request.args.get('file_id', type=int)
    limit = request.args.get('limit', 100, type=int)
    limit = max(1, min(limit, 500))  # Enforce range: 1-500
    smart_search = request.args.get('smart', 'true').lower() == 'true'

    if not query_text:
        return jsonify({'error': 'Search query required'}), 400

    # Expand query using smart keywords
    if smart_search:
        search_terms = expand_search_query(query_text)
    else:
        search_terms = [query_text]

    # Build OR query for all search terms
    from sqlalchemy import or_
    search_conditions = [LogEntry.raw_content.ilike(f'%{term}%') for term in search_terms]
    query = LogEntry.query.filter(or_(*search_conditions))

    if file_id:
        query = query.filter_by(log_file_id=file_id)
    if severity:
        query = query.filter_by(severity=severity)
    if service:
        query = query.filter_by(service=service)

    entries = query.order_by(LogEntry.line_number).limit(limit).all()

    return jsonify({
        'query': query_text,
        'search_terms': search_terms,
        'smart_search': smart_search,
        'count': len(entries),
        'entries': [e.to_dict() for e in entries]
    })


@api_bp.route('/services', methods=['GET'])
def get_services():
    """Get list of all unique services across log files"""
    file_id = request.args.get('file_id', type=int)

    query = db.session.query(LogEntry.service).distinct()
    if file_id:
        query = query.filter_by(log_file_id=file_id)

    services = [s[0] for s in query.all() if s[0]]
    return jsonify(services)


@api_bp.route('/summary', methods=['GET'])
def get_summary():
    """Get overall summary statistics"""
    total_files = LogFile.query.count()
    total_entries = LogEntry.query.count()
    total_issues = Issue.query.count()

    # Issues by severity
    issues_by_severity = {}
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = Issue.query.filter_by(severity=severity).count()
        issues_by_severity[severity] = count

    # Recent issues
    recent_issues = Issue.query.order_by(Issue.created_at.desc()).limit(5).all()

    return jsonify({
        'total_files': total_files,
        'total_entries': total_entries,
        'total_issues': total_issues,
        'issues_by_severity': issues_by_severity,
        'recent_issues': [i.to_dict() for i in recent_issues]
    })


@api_bp.route('/log-files/<int:file_id>/health', methods=['GET'])
def get_health_score(file_id):
    """Get health score for a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    entries = LogEntry.query.filter_by(log_file_id=file_id).all()
    entries_data = [e.to_dict() for e in entries]

    issues = Issue.query.filter_by(log_file_id=file_id).all()
    issues_data = [i.to_dict() for i in issues]

    detector = IssueDetector()
    health_score = detector.get_health_score(entries_data, issues_data)

    return jsonify(health_score)


@api_bp.route('/log-files/<int:file_id>/export', methods=['GET'])
def export_log_file(file_id):
    """Export log file analysis in various formats"""
    log_file = LogFile.query.get_or_404(file_id)
    export_format = request.args.get('format', 'json')

    entries = LogEntry.query.filter_by(log_file_id=file_id).all()
    issues = Issue.query.filter_by(log_file_id=file_id).all()

    if export_format == 'json':
        data = {
            'log_file': log_file.to_dict(),
            'entries': [e.to_dict() for e in entries],
            'issues': [i.to_dict() for i in issues]
        }
        return jsonify(data)

    elif export_format == 'csv':
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['line_number', 'timestamp', 'severity', 'service', 'command', 'message'])

        # Write entries
        for entry in entries:
            writer.writerow([
                entry.line_number,
                entry.timestamp.isoformat() if entry.timestamp else '',
                entry.severity or '',
                entry.service or '',
                entry.command or '',
                entry.message or ''
            ])

        from flask import Response
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=log_{file_id}.csv'
        return response

    elif export_format == 'summary':
        # Export just the summary/issues
        detector = IssueDetector()
        entries_data = [e.to_dict() for e in entries]
        issues_data = [i.to_dict() for i in issues]
        health_score = detector.get_health_score(entries_data, issues_data)

        summary = {
            'file': log_file.original_filename,
            'health_score': health_score,
            'total_lines': log_file.total_lines,
            'error_count': log_file.error_count,
            'warning_count': log_file.warning_count,
            'issues': issues_data
        }
        return jsonify(summary)

    return jsonify({'error': 'Invalid format'}), 400


@api_bp.route('/log-files/<int:file_id>/patterns', methods=['GET'])
def get_patterns(file_id):
    """Get detected patterns in a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    entries = LogEntry.query.filter_by(log_file_id=file_id).all()
    entries_data = [e.to_dict() for e in entries]

    detector = IssueDetector()
    patterns = detector.detect_patterns(entries_data)

    return jsonify(patterns)


@api_bp.route('/log-files/<int:file_id>/sequences', methods=['GET'])
def get_error_sequences(file_id):
    """Get error sequences (cascading failures) in a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.timestamp).all()
    entries_data = [e.to_dict() for e in entries]

    detector = IssueDetector()
    window = request.args.get('window', 5, type=int)
    window = max(1, min(window, 60))  # Enforce range: 1-60 minutes
    sequences = detector.detect_error_sequences(entries_data, window_minutes=window)

    # Convert datetime objects to strings for JSON serialization
    for seq in sequences:
        seq['start_time'] = seq['start_time'].isoformat() if seq.get('start_time') else None
        seq['end_time'] = seq['end_time'].isoformat() if seq.get('end_time') else None
        seq['entries'] = [
            {
                'line_number': e.get('line_number'),
                'timestamp': e.get('timestamp').isoformat() if e.get('timestamp') else None,
                'severity': e.get('severity'),
                'service': e.get('service'),
                'message': e.get('message', '')[:100]
            }
            for e in seq.get('entries', [])
        ]

    return jsonify({
        'sequences': sequences,
        'count': len(sequences)
    })


@api_bp.route('/log-files/<int:file_id>/service-health', methods=['GET'])
def get_service_health(file_id):
    """Get health metrics for each service in a log file"""
    log_file = LogFile.query.get_or_404(file_id)

    # Get entries grouped by service
    from sqlalchemy import func

    service_stats = db.session.query(
        LogEntry.service,
        func.count(LogEntry.id).label('total'),
        func.sum(
            db.case(
                (LogEntry.severity.in_(['CRITICAL', 'ERROR']), 1),
                else_=0
            )
        ).label('errors'),
        func.sum(
            db.case(
                (LogEntry.severity == 'WARNING', 1),
                else_=0
            )
        ).label('warnings')
    ).filter_by(log_file_id=file_id).group_by(LogEntry.service).all()

    services = []
    for stat in service_stats:
        if stat.service:
            total = stat.total or 0
            errors = stat.errors or 0
            warnings = stat.warnings or 0

            error_rate = (errors / total * 100) if total > 0 else 0
            health_score = max(0, 100 - (error_rate * 5))

            services.append({
                'name': stat.service,
                'total_entries': total,
                'error_count': errors,
                'warning_count': warnings,
                'error_rate': round(error_rate, 2),
                'health_score': round(health_score, 1),
                'status': 'good' if health_score >= 80 else ('warning' if health_score >= 60 else 'critical')
            })

    # Sort by health score (worst first)
    services.sort(key=lambda x: x['health_score'])

    return jsonify({
        'services': services,
        'count': len(services)
    })


@api_bp.route('/severity-info', methods=['GET'])
def get_severity_info():
    """Get information about severity levels"""
    detector = IssueDetector()
    return jsonify(detector.get_all_severity_info())


@api_bp.route('/category-info', methods=['GET'])
def get_category_info():
    """Get information about issue categories"""
    detector = IssueDetector()
    return jsonify(detector.get_all_category_info())


@api_bp.route('/log-files/compare', methods=['POST'])
def compare_log_files():
    """Compare error patterns between multiple log files"""
    data = request.get_json()
    file_ids = data.get('file_ids', [])

    if len(file_ids) < 2:
        return jsonify({'error': 'At least 2 file IDs required'}), 400

    comparisons = []

    for file_id in file_ids:
        log_file = LogFile.query.get(file_id)
        if not log_file:
            continue

        issues = Issue.query.filter_by(log_file_id=file_id).all()

        comparisons.append({
            'file_id': file_id,
            'filename': log_file.original_filename,
            'total_lines': log_file.total_lines,
            'error_count': log_file.error_count,
            'warning_count': log_file.warning_count,
            'issue_count': len(issues),
            'issues_by_category': {},
            'issues_by_severity': {}
        })

        for issue in issues:
            cat = issue.category or 'unknown'
            sev = issue.severity or 'unknown'

            if cat not in comparisons[-1]['issues_by_category']:
                comparisons[-1]['issues_by_category'][cat] = 0
            comparisons[-1]['issues_by_category'][cat] += 1

            if sev not in comparisons[-1]['issues_by_severity']:
                comparisons[-1]['issues_by_severity'][sev] = 0
            comparisons[-1]['issues_by_severity'][sev] += 1

    # Find common issues
    all_categories = set()
    for comp in comparisons:
        all_categories.update(comp['issues_by_category'].keys())

    common_issues = []
    for cat in all_categories:
        counts = [comp['issues_by_category'].get(cat, 0) for comp in comparisons]
        if all(c > 0 for c in counts):
            common_issues.append({
                'category': cat,
                'occurrences': counts
            })

    return jsonify({
        'comparisons': comparisons,
        'common_issues': common_issues
    })


@api_bp.route('/log-files/<int:file_id>/ai-search', methods=['POST'])
def ai_search(file_id):
    """
    AI-powered intelligent search for log analysis.

    Understands natural language queries like:
    - "Why is the camera not recording?"
    - "Show me the boot flow"
    - "Find upload errors"
    - "What happened with GPS?"
    """
    from app.services import IntelligentSearch

    log_file = LogFile.query.get_or_404(file_id)
    data = request.get_json()

    query = data.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query is required'}), 400

    # Get all log entries for this file
    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()

    # Convert to dict format
    entries_data = []
    for entry in entries:
        entries_data.append({
            'line_number': entry.line_number,
            'timestamp': entry.timestamp,
            'severity': entry.severity,
            'service': entry.service,
            'component': entry.component,
            'message': entry.message,
            'raw_content': entry.raw_content
        })

    # Run intelligent search
    searcher = IntelligentSearch()
    result = searcher.search(query, entries_data)

    return jsonify(result)


@api_bp.route('/ai/status', methods=['GET'])
def ai_status():
    """Get AI agent status including provider info."""
    from app.services import get_ai_agent

    agent = get_ai_agent()
    status = agent.get_status()
    return jsonify(status)


@api_bp.route('/log-files/<int:file_id>/deep-analysis', methods=['POST'])
def deep_analysis(file_id):
    """
    AI-powered deep analysis using Claude API.

    Performs intelligent root cause analysis with contextual conversation.
    Supports caching - if the same query was run before, returns cached result.
    Use force_refresh=true to bypass cache.
    """
    from app.services import IntelligentSearch, get_ai_agent

    log_file = LogFile.query.get_or_404(file_id)
    data = request.get_json()

    query = data.get('query', '').strip()
    session_id = data.get('session_id', f'file_{file_id}')
    force_refresh = data.get('force_refresh', False)

    if not query:
        return jsonify({'error': 'Query is required'}), 400

    # Check for cached analysis first (unless force_refresh is requested)
    query_hash = AIAnalysisCache.generate_hash(query)
    if not force_refresh:
        cached = db.session.query(AIAnalysisCache).filter_by(
            log_file_id=file_id,
            query_hash=query_hash
        ).first()

        if cached:
            # Return cached result
            result = cached.to_dict()
            result['success'] = True
            result['analysis'] = cached.analysis_result
            result['from_cache'] = True
            result['cached_at'] = cached.created_at.isoformat() if cached.created_at else None
            result['quick_search'] = {
                'topics': [],
                'total_matches': 0,
                'error_count': 0,
                'flow_detected': None
            }
            return jsonify(result)

    # Get AI agent
    agent = get_ai_agent()

    # Check if AI is available
    if not agent.is_available():
        return jsonify({
            'success': False,
            'error': 'AI Agent not available. Please set ANTHROPIC_API_KEY environment variable.',
            'ai_available': False
        }), 503

    # First, run quick local search to find relevant entries
    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()
    entries_data = []
    for entry in entries:
        entries_data.append({
            'line_number': entry.line_number,
            'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
            'level': entry.severity,
            'service': entry.service,
            'component': entry.component,
            'message': entry.message,
            'content': entry.raw_content,
            'raw_content': entry.raw_content  # Include raw log line
        })

    # Run quick search first
    searcher = IntelligentSearch()
    quick_results = searcher.search(query, entries_data)

    # Get relevant entries for deep analysis - prioritize errors and warnings
    relevant_entries = []
    if quick_results.get('matches'):
        # Use matched entries from quick search
        for match in quick_results['matches'][:100]:
            relevant_entries.append(match)
    else:
        # Prioritize errors and warnings when no specific matches
        errors = [e for e in entries_data if (e.get('level') or '').upper() in ('ERROR', 'CRITICAL', 'FATAL')]
        warnings = [e for e in entries_data if (e.get('level') or '').upper() in ('WARNING', 'WARN')]
        info = [e for e in entries_data if (e.get('level') or '').upper() not in ('ERROR', 'CRITICAL', 'FATAL', 'WARNING', 'WARN')]
        relevant_entries = errors + warnings + info[:max(0, 100 - len(errors) - len(warnings))]
        relevant_entries = relevant_entries[:100]

    # Perform deep AI analysis
    result = agent.analyze(
        query=query,
        log_entries=relevant_entries,
        session_id=session_id,
        quick_search_results=quick_results
    )

    # Add quick search results to response
    result['quick_search'] = {
        'topics': quick_results.get('topics', []),
        'total_matches': quick_results.get('total_matches', 0),
        'error_count': quick_results.get('error_count', 0),
        'flow_detected': quick_results.get('flow_detected')
    }

    # Include relevant log entries with context (10 lines before/after each error/warning)
    errors_warnings = [e for e in relevant_entries if e.get('level', '').upper() in ('ERROR', 'CRITICAL', 'FATAL', 'WARNING', 'WARN')]

    # Build context around errors/warnings
    context_lines = set()
    for entry in errors_warnings:
        line_num = entry.get('line_number', 0)
        # Add 10 lines before and after
        for i in range(max(1, line_num - 10), line_num + 11):
            context_lines.add(i)

    # Get all entries that fall within context ranges
    logs_with_context = []
    for entry in entries_data:
        if entry.get('line_number') in context_lines:
            # Mark if this is an error/warning line
            level = (entry.get('level') or '').upper()
            entry['is_issue'] = level in ('ERROR', 'CRITICAL', 'FATAL', 'WARNING', 'WARN')
            logs_with_context.append(entry)

    # Sort by line number
    logs_with_context.sort(key=lambda x: x.get('line_number', 0))

    result['relevant_logs'] = logs_with_context[:200]  # Limit to 200 entries with context

    # Cache the successful result with proper transaction handling
    if result.get('success'):
        try:
            from sqlalchemy.exc import IntegrityError

            # Use a transaction with proper isolation to handle race conditions
            cache_entry = AIAnalysisCache(
                log_file_id=file_id,
                query=query[:500],  # Truncate if needed
                query_hash=query_hash,
                analysis_result=result.get('analysis', ''),
                relevant_logs=json.dumps(logs_with_context[:200]),
                providers_used=','.join(result.get('providers_used', [])),
                provider_count=result.get('provider_count', 1),
                logs_analyzed=result.get('logs_analyzed', len(relevant_entries))
            )

            try:
                db.session.add(cache_entry)
                db.session.commit()
                result['cached'] = True
            except IntegrityError:
                # Race condition: another request created the cache entry
                db.session.rollback()
                # Update the existing entry instead
                existing = db.session.query(AIAnalysisCache).filter_by(
                    log_file_id=file_id,
                    query_hash=query_hash
                ).first()
                if existing:
                    existing.analysis_result = result.get('analysis', '')
                    existing.relevant_logs = json.dumps(logs_with_context[:200])
                    existing.providers_used = ','.join(result.get('providers_used', []))
                    existing.provider_count = result.get('provider_count', 1)
                    existing.logs_analyzed = result.get('logs_analyzed', len(relevant_entries))
                    existing.created_at = datetime.utcnow()
                    db.session.commit()
                result['cached'] = True
        except Exception as e:
            # Don't fail the request if caching fails
            db.session.rollback()
            result['cache_error'] = str(e)

    result['from_cache'] = False
    return jsonify(result)


@api_bp.route('/log-files/<int:file_id>/ai-followup', methods=['POST'])
def ai_followup(file_id):
    """
    Continue conversation with AI agent using previous context.
    """
    from app.services import get_ai_agent

    log_file = LogFile.query.get_or_404(file_id)
    data = request.get_json()

    query = data.get('query', '').strip()
    session_id = data.get('session_id', f'file_{file_id}')

    if not query:
        return jsonify({'error': 'Query is required'}), 400

    agent = get_ai_agent()

    if not agent.is_available():
        return jsonify({
            'success': False,
            'error': 'AI Agent not available.',
            'ai_available': False
        }), 503

    result = agent.ask_followup(query, session_id)
    return jsonify(result)


@api_bp.route('/log-files/<int:file_id>/raw', methods=['GET'])
def get_raw_log(file_id):
    """Get the full raw log file content."""
    from flask import current_app

    log_file = LogFile.query.get_or_404(file_id)

    # Read the raw file
    file_path = current_app.config['UPLOAD_FOLDER'] / log_file.filename
    if not file_path.exists():
        return jsonify({'error': 'Log file not found'}), 404

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Also get entries with line numbers for reference
        entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()
        lines_info = []
        for entry in entries:
            level = (entry.severity or '').upper()
            lines_info.append({
                'line_number': entry.line_number,
                'level': level,
                'is_issue': level in ('ERROR', 'CRITICAL', 'FATAL', 'WARNING', 'WARN')
            })

        return jsonify({
            'filename': log_file.original_filename,
            'content': content,
            'total_lines': log_file.total_lines,
            'lines_info': lines_info
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/ai-agent/status', methods=['GET'])
def ai_agent_status():
    """Get AI agent status and availability."""
    from app.services import get_ai_agent

    agent = get_ai_agent()
    return jsonify(agent.get_status())


@api_bp.route('/ai-agent/clear-conversation', methods=['POST'])
def clear_ai_conversation():
    """Clear conversation history for a session."""
    from app.services import get_ai_agent

    data = request.get_json()
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({'error': 'session_id required'}), 400

    agent = get_ai_agent()
    agent.clear_conversation(session_id)

    return jsonify({'success': True, 'message': 'Conversation cleared'})


@api_bp.route('/log-files/<int:file_id>/reparse', methods=['POST'])
def reparse_log_file(file_id):
    """Re-parse a log file with current parser settings."""
    log_file = LogFile.query.get_or_404(file_id)

    # Get the file path
    file_path = current_app.config['UPLOAD_FOLDER'] / log_file.filename
    if not file_path.exists():
        return jsonify({'error': 'Log file not found on disk'}), 404

    # Use a single transaction for the entire reparse operation
    # This ensures atomicity - either everything succeeds or nothing changes
    try:
        # Re-parse the file first (before deleting anything)
        parser = LogParser()
        entries, stats = parser.parse_file_full(file_path)

        # Now delete existing entries and issues within the transaction
        LogEntry.query.filter_by(log_file_id=file_id).delete()
        Issue.query.filter_by(log_file_id=file_id).delete()

        # Save new entries
        for entry_data in entries:
            entry = LogEntry(
                log_file_id=file_id,
                line_number=entry_data.get('line_number'),
                timestamp=entry_data.get('timestamp'),
                severity=entry_data.get('severity'),
                service=entry_data.get('service'),
                component=entry_data.get('component'),
                command=entry_data.get('command'),
                message=entry_data.get('message'),
                raw_content=entry_data.get('raw_content')
            )
            db.session.add(entry)

        # Update log file stats from parser stats
        error_count = stats.get('error_count', 0) + stats.get('critical_count', 0)
        warning_count = stats.get('warning_count', 0)
        log_file.total_lines = stats.get('total_lines', len(entries))
        log_file.error_count = error_count
        log_file.warning_count = warning_count

        # Flush to get the entries in the session
        db.session.flush()

        # Re-detect issues
        detector = IssueDetector()
        entries_data = [e.to_dict() for e in LogEntry.query.filter_by(log_file_id=file_id).all()]
        detected_issues = detector.detect_issues(entries_data)

        for issue_data in detected_issues:
            # Convert timestamp strings to datetime objects if needed
            first_occ = issue_data.get('first_occurrence')
            last_occ = issue_data.get('last_occurrence')
            if isinstance(first_occ, str):
                try:
                    first_occ = datetime.fromisoformat(first_occ)
                except ValueError:
                    first_occ = None
            if isinstance(last_occ, str):
                try:
                    last_occ = datetime.fromisoformat(last_occ)
                except ValueError:
                    last_occ = None

            issue = Issue(
                log_file_id=file_id,
                title=issue_data.get('title'),
                description=issue_data.get('description'),
                severity=issue_data.get('severity'),
                category=issue_data.get('category'),
                affected_lines=json.dumps(issue_data.get('affected_lines', [])),
                first_occurrence=first_occ,
                last_occurrence=last_occ,
                occurrence_count=issue_data.get('occurrence_count', 1)
            )
            db.session.add(issue)

        # Commit the entire transaction
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Reparse failed: {str(e)}'}), 500

    return jsonify({
        'success': True,
        'message': 'Log file re-parsed successfully',
        'total_lines': len(entries),
        'error_count': error_count,
        'warning_count': warning_count,
        'issues_detected': len(detected_issues)
    })


# ============================================
# Export Endpoints
# ============================================

@api_bp.route('/log-files/<int:file_id>/export/csv', methods=['GET'])
def export_log_csv(file_id):
    """Export log entries as CSV."""
    from flask import Response
    import csv
    import io

    log_file = LogFile.query.get_or_404(file_id)
    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Line', 'Timestamp', 'Severity', 'Service', 'Message', 'Raw Content'])

    for entry in entries:
        writer.writerow([
            entry.line_number,
            entry.timestamp.isoformat() if entry.timestamp else '',
            entry.severity or '',
            entry.service or '',
            entry.message or '',
            entry.raw_content or ''
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={log_file.original_filename}_export.csv'}
    )


@api_bp.route('/log-files/<int:file_id>/export/json', methods=['GET'])
def export_log_json(file_id):
    """Export log entries as JSON."""
    from flask import Response

    log_file = LogFile.query.get_or_404(file_id)
    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()

    export_data = {
        'file': log_file.to_dict(),
        'entries': [e.to_dict() for e in entries],
        'exported_at': datetime.utcnow().isoformat()
    }

    return Response(
        json.dumps(export_data, indent=2, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={log_file.original_filename}_export.json'}
    )


@api_bp.route('/issues/<int:issue_id>/export/<format>', methods=['GET'])
def export_issue(issue_id, format):
    """Export issue as Jira, GitHub, or Markdown format."""
    issue = Issue.query.get_or_404(issue_id)
    log_file = LogFile.query.get(issue.log_file_id)

    generator = BugReportGenerator()
    report = generator.generate_report(
        issue.to_dict(),
        device_info={'filename': log_file.original_filename if log_file else 'Unknown'},
        template_name=format
    )

    if format == 'json':
        return jsonify(report)
    else:
        return jsonify({
            'title': report['title'],
            'body': report['description'],
            'format': format
        })


@api_bp.route('/bug-reports/<int:report_id>/export/<format>', methods=['GET'])
def export_bug_report(report_id, format):
    """Export bug report in specified format."""
    report = BugReport.query.get_or_404(report_id)

    if format == 'jira':
        # Jira format
        content = f"""h2. {report.title}

h3. Description
{report.description}

h3. Steps to Reproduce
{report.steps_to_reproduce or 'Not specified'}

h3. Expected Behavior
{report.expected_behavior or 'Not specified'}

h3. Actual Behavior
{report.actual_behavior or 'Not specified'}

h3. Environment
{report.environment or 'Not specified'}

h3. Log Snippets
{{code}}
{report.log_snippets or 'No log snippets'}
{{code}}

_Severity: {report.severity}_
_Category: {report.category}_
_Status: {report.status}_
"""
    elif format == 'github':
        # GitHub format
        content = f"""### {report.title}

**Severity:** {report.severity}
**Category:** {report.category}
**Status:** {report.status}

### Description
{report.description}

### Steps to Reproduce
{report.steps_to_reproduce or 'Not specified'}

### Expected Behavior
{report.expected_behavior or 'Not specified'}

### Actual Behavior
{report.actual_behavior or 'Not specified'}

### Environment
{report.environment or 'Not specified'}

### Log Snippets
```
{report.log_snippets or 'No log snippets'}
```

---
<sub>Generated by Sentinel Logger</sub>
"""
    else:
        # Markdown format (default)
        content = f"""# {report.title}

**Severity:** {report.severity}
**Category:** {report.category}
**Status:** {report.status}

## Description
{report.description}

## Steps to Reproduce
{report.steps_to_reproduce or 'Not specified'}

## Expected Behavior
{report.expected_behavior or 'Not specified'}

## Actual Behavior
{report.actual_behavior or 'Not specified'}

## Environment
{report.environment or 'Not specified'}

## Log Snippets
```
{report.log_snippets or 'No log snippets'}
```
"""

    return jsonify({
        'title': report.title,
        'content': content,
        'format': format
    })


# ============================================
# Log Comparison Endpoints
# ============================================

@api_bp.route('/compare', methods=['POST'])
def compare_logs():
    """Compare two log files and return differences."""
    data = request.get_json()
    file1_id = data.get('file1_id')
    file2_id = data.get('file2_id')

    if not file1_id or not file2_id:
        return jsonify({'error': 'Both file IDs required'}), 400

    file1 = LogFile.query.get_or_404(file1_id)
    file2 = LogFile.query.get_or_404(file2_id)

    # Get entries
    entries1 = LogEntry.query.filter_by(log_file_id=file1_id).order_by(LogEntry.line_number).all()
    entries2 = LogEntry.query.filter_by(log_file_id=file2_id).order_by(LogEntry.line_number).all()

    # Get issues
    issues1 = Issue.query.filter_by(log_file_id=file1_id).all()
    issues2 = Issue.query.filter_by(log_file_id=file2_id).all()

    # Count severities
    def count_severities(entries):
        counts = {'CRITICAL': 0, 'ERROR': 0, 'WARNING': 0, 'INFO': 0, 'DEBUG': 0}
        for e in entries:
            sev = (e.severity or 'INFO').upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    sev1 = count_severities(entries1)
    sev2 = count_severities(entries2)

    # Find common and unique issues
    issues1_titles = set(i.title for i in issues1)
    issues2_titles = set(i.title for i in issues2)
    common_issues = issues1_titles & issues2_titles
    only_in_file1 = issues1_titles - issues2_titles
    only_in_file2 = issues2_titles - issues1_titles

    return jsonify({
        'file1': {
            'id': file1.id,
            'name': file1.original_filename,
            'total_lines': file1.total_lines,
            'error_count': file1.error_count,
            'warning_count': file1.warning_count,
            'severities': sev1,
            'issue_count': len(issues1)
        },
        'file2': {
            'id': file2.id,
            'name': file2.original_filename,
            'total_lines': file2.total_lines,
            'error_count': file2.error_count,
            'warning_count': file2.warning_count,
            'severities': sev2,
            'issue_count': len(issues2)
        },
        'comparison': {
            'common_issues': list(common_issues),
            'only_in_file1': list(only_in_file1),
            'only_in_file2': list(only_in_file2),
            'error_diff': sev2['ERROR'] - sev1['ERROR'],
            'warning_diff': sev2['WARNING'] - sev1['WARNING']
        }
    })


# ============================================
# System Monitoring Endpoints
# ============================================

# Store previous network stats for calculating speeds
_prev_net_io = None
_prev_net_time = None


@api_bp.route('/system/stats', methods=['GET'])
def get_system_stats():
    """
    Get current system statistics including CPU, memory, and network usage.
    Returns real-time data for system monitoring widgets.
    """
    global _prev_net_io, _prev_net_time

    if not PSUTIL_AVAILABLE:
        return jsonify({
            'available': False,
            'error': 'psutil library is not installed. Run: pip install psutil'
        }), 503

    try:
        import time

        # CPU Usage (percentage, averaged over 1 second interval)
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        cpu_count_logical = psutil.cpu_count(logical=True)

        # Memory Usage
        memory = psutil.virtual_memory()
        memory_used_gb = memory.used / (1024 ** 3)
        memory_total_gb = memory.total / (1024 ** 3)
        memory_percent = memory.percent

        # Network Usage
        net_io = psutil.net_io_counters()
        current_time = time.time()

        # Calculate network speeds (bytes per second)
        bytes_sent_speed = 0
        bytes_recv_speed = 0

        if _prev_net_io is not None and _prev_net_time is not None:
            time_delta = current_time - _prev_net_time
            if time_delta > 0:
                bytes_sent_speed = (net_io.bytes_sent - _prev_net_io.bytes_sent) / time_delta
                bytes_recv_speed = (net_io.bytes_recv - _prev_net_io.bytes_recv) / time_delta

        # Store current values for next calculation
        _prev_net_io = net_io
        _prev_net_time = current_time

        # Format network speeds
        def format_bytes(bytes_val):
            """Format bytes to human readable format"""
            if bytes_val < 1024:
                return f"{bytes_val:.0f} B/s"
            elif bytes_val < 1024 ** 2:
                return f"{bytes_val / 1024:.1f} KB/s"
            elif bytes_val < 1024 ** 3:
                return f"{bytes_val / (1024 ** 2):.1f} MB/s"
            else:
                return f"{bytes_val / (1024 ** 3):.2f} GB/s"

        def format_total_bytes(bytes_val):
            """Format total bytes to human readable format"""
            if bytes_val < 1024:
                return f"{bytes_val:.0f} B"
            elif bytes_val < 1024 ** 2:
                return f"{bytes_val / 1024:.1f} KB"
            elif bytes_val < 1024 ** 3:
                return f"{bytes_val / (1024 ** 2):.1f} MB"
            else:
                return f"{bytes_val / (1024 ** 3):.2f} GB"

        return jsonify({
            'available': True,
            'cpu': {
                'percent': round(cpu_percent, 1),
                'cores': cpu_count,
                'logical_cores': cpu_count_logical
            },
            'memory': {
                'percent': round(memory_percent, 1),
                'used_gb': round(memory_used_gb, 2),
                'total_gb': round(memory_total_gb, 2),
                'used_formatted': f"{memory_used_gb:.1f} GB",
                'total_formatted': f"{memory_total_gb:.1f} GB"
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'bytes_sent_speed': round(bytes_sent_speed, 0),
                'bytes_recv_speed': round(bytes_recv_speed, 0),
                'sent_speed_formatted': format_bytes(bytes_sent_speed),
                'recv_speed_formatted': format_bytes(bytes_recv_speed),
                'total_sent_formatted': format_total_bytes(net_io.bytes_sent),
                'total_recv_formatted': format_total_bytes(net_io.bytes_recv)
            },
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        return jsonify({
            'available': False,
            'error': str(e)
        }), 500


# ============================================
# Saved Queries Endpoints
# ============================================

@api_bp.route('/saved-queries', methods=['GET'])
def get_saved_queries():
    """Get all saved queries, optionally filtered by category."""
    category = request.args.get('category')

    query = SavedQuery.query
    if category:
        query = query.filter_by(category=category)

    queries = query.order_by(SavedQuery.use_count.desc(), SavedQuery.name).all()
    return jsonify([q.to_dict() for q in queries])


@api_bp.route('/saved-queries', methods=['POST'])
def create_saved_query():
    """Create a new saved query."""
    data = request.get_json()

    if not data.get('name') or not data.get('query'):
        return jsonify({'error': 'Name and query are required'}), 400

    saved_query = SavedQuery(
        name=data['name'],
        query=data['query'],
        description=data.get('description'),
        category=data.get('category', 'custom'),
        icon=data.get('icon', 'bi-search'),
        is_default=False
    )
    db.session.add(saved_query)
    db.session.commit()

    return jsonify(saved_query.to_dict()), 201


@api_bp.route('/saved-queries/<int:query_id>', methods=['GET'])
def get_saved_query(query_id):
    """Get a specific saved query."""
    query = SavedQuery.query.get_or_404(query_id)
    return jsonify(query.to_dict())


@api_bp.route('/saved-queries/<int:query_id>', methods=['PUT'])
def update_saved_query(query_id):
    """Update a saved query."""
    saved_query = SavedQuery.query.get_or_404(query_id)

    if saved_query.is_default:
        return jsonify({'error': 'Cannot modify default queries'}), 403

    data = request.get_json()

    if 'name' in data:
        saved_query.name = data['name']
    if 'query' in data:
        saved_query.query = data['query']
    if 'description' in data:
        saved_query.description = data['description']
    if 'category' in data:
        saved_query.category = data['category']
    if 'icon' in data:
        saved_query.icon = data['icon']

    db.session.commit()
    return jsonify(saved_query.to_dict())


@api_bp.route('/saved-queries/<int:query_id>', methods=['DELETE'])
def delete_saved_query(query_id):
    """Delete a saved query."""
    saved_query = SavedQuery.query.get_or_404(query_id)

    if saved_query.is_default:
        return jsonify({'error': 'Cannot delete default queries'}), 403

    db.session.delete(saved_query)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Query deleted'})


@api_bp.route('/saved-queries/<int:query_id>/use', methods=['POST'])
def use_saved_query(query_id):
    """Increment use count for a saved query."""
    saved_query = SavedQuery.query.get_or_404(query_id)
    saved_query.use_count += 1
    db.session.commit()

    return jsonify(saved_query.to_dict())


@api_bp.route('/saved-queries/seed-defaults', methods=['POST'])
def seed_default_queries():
    """Seed default analysis queries."""
    defaults = [
        {
            'name': 'Full Analysis',
            'query': 'Analyze this log file and find all issues. Explain each problem in simple terms for a QA tester.',
            'description': 'Comprehensive analysis of all log entries',
            'category': 'general',
            'icon': 'bi-search'
        },
        {
            'name': 'Boot Issues',
            'query': 'Show me the boot sequence and identify any boot-related issues, startup failures, or initialization problems.',
            'description': 'Analyze boot and startup sequence',
            'category': 'boot',
            'icon': 'bi-power'
        },
        {
            'name': 'Camera Problems',
            'query': 'Find any camera or video recording issues. Look for capture failures, encoding problems, or video quality issues.',
            'description': 'Video and camera system analysis',
            'category': 'camera',
            'icon': 'bi-camera-video'
        },
        {
            'name': 'Network Issues',
            'query': 'Find any network, WiFi, or connectivity problems. Look for connection failures, timeouts, or data transfer issues.',
            'description': 'Network connectivity analysis',
            'category': 'network',
            'icon': 'bi-wifi'
        },
        {
            'name': 'Storage Issues',
            'query': 'Find any storage, SD card, or disk problems. Look for write failures, mount issues, or space problems.',
            'description': 'Storage and filesystem analysis',
            'category': 'storage',
            'icon': 'bi-hdd'
        },
        {
            'name': 'Crash Analysis',
            'query': 'Find any crashes, panics, or fatal errors. Identify the root cause and affected components.',
            'description': 'System crash and error analysis',
            'category': 'crash',
            'icon': 'bi-exclamation-triangle'
        },
        {
            'name': 'OTA Update',
            'query': 'Analyze the firmware/OTA update process. Look for download failures, verification issues, or installation problems.',
            'description': 'Firmware update analysis',
            'category': 'ota',
            'icon': 'bi-cloud-download'
        },
        {
            'name': 'Memory Issues',
            'query': 'Find any memory-related problems like out-of-memory conditions, memory leaks, or allocation failures.',
            'description': 'Memory and resource analysis',
            'category': 'memory',
            'icon': 'bi-memory'
        }
    ]

    created = 0
    for default in defaults:
        existing = SavedQuery.query.filter_by(name=default['name'], is_default=True).first()
        if not existing:
            query = SavedQuery(
                name=default['name'],
                query=default['query'],
                description=default['description'],
                category=default['category'],
                icon=default['icon'],
                is_default=True
            )
            db.session.add(query)
            created += 1

    db.session.commit()
    return jsonify({'success': True, 'created': created})


# ============================================
# Log Annotations Endpoints
# ============================================

@api_bp.route('/log-files/<int:file_id>/annotations', methods=['GET'])
def get_annotations(file_id):
    """Get all annotations for a log file."""
    log_file = LogFile.query.get_or_404(file_id)
    annotations = LogAnnotation.query.filter_by(log_file_id=file_id).order_by(LogAnnotation.line_number).all()
    return jsonify([a.to_dict() for a in annotations])


@api_bp.route('/log-files/<int:file_id>/annotations', methods=['POST'])
def create_annotation(file_id):
    """Create an annotation on a log line."""
    log_file = LogFile.query.get_or_404(file_id)
    data = request.get_json()

    if not data.get('line_number') or not data.get('note'):
        return jsonify({'error': 'Line number and note are required'}), 400

    annotation = LogAnnotation(
        log_file_id=file_id,
        line_number=data['line_number'],
        note=data['note'],
        annotation_type=data.get('annotation_type', 'note')
    )
    db.session.add(annotation)
    db.session.commit()

    return jsonify(annotation.to_dict()), 201


@api_bp.route('/annotations/<int:annotation_id>', methods=['PUT'])
def update_annotation(annotation_id):
    """Update an annotation."""
    annotation = LogAnnotation.query.get_or_404(annotation_id)
    data = request.get_json()

    if 'note' in data:
        annotation.note = data['note']
    if 'annotation_type' in data:
        annotation.annotation_type = data['annotation_type']

    db.session.commit()
    return jsonify(annotation.to_dict())


@api_bp.route('/annotations/<int:annotation_id>', methods=['DELETE'])
def delete_annotation(annotation_id):
    """Delete an annotation."""
    annotation = LogAnnotation.query.get_or_404(annotation_id)
    db.session.delete(annotation)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Annotation deleted'})


# ============================================
# Shared Analysis Links Endpoints
# ============================================

@api_bp.route('/shared', methods=['POST'])
def create_shared_link():
    """Create a shareable link for an analysis."""
    data = request.get_json()

    log_file_id = data.get('log_file_id')
    if not log_file_id:
        return jsonify({'error': 'log_file_id is required'}), 400

    log_file = LogFile.query.get_or_404(log_file_id)

    # Create shared analysis
    share_id = SharedAnalysis.generate_share_id()
    shared = SharedAnalysis(
        share_id=share_id,
        log_file_id=log_file_id,
        analysis_cache_id=data.get('analysis_cache_id'),
        title=data.get('title', log_file.original_filename)
    )

    # Set expiration if provided (in hours)
    expires_hours = data.get('expires_hours')
    if expires_hours:
        from datetime import timedelta
        shared.expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    db.session.add(shared)
    db.session.commit()

    return jsonify(shared.to_dict()), 201


@api_bp.route('/shared/<share_id>', methods=['GET'])
def get_shared_analysis(share_id):
    """Get a shared analysis by share ID."""
    shared = SharedAnalysis.query.filter_by(share_id=share_id).first()

    if not shared:
        return jsonify({'error': 'Shared analysis not found'}), 404

    # Check if expired
    if shared.expires_at and shared.expires_at < datetime.utcnow():
        return jsonify({'error': 'Shared link has expired'}), 410

    # Increment view count
    shared.view_count += 1
    db.session.commit()

    # Get log file and analysis data
    log_file = LogFile.query.get(shared.log_file_id)
    analysis_cache = None
    if shared.analysis_cache_id:
        analysis_cache = db.session.get(AIAnalysisCache, shared.analysis_cache_id)

    result = shared.to_dict()
    result['log_file'] = log_file.to_dict() if log_file else None
    result['analysis'] = analysis_cache.to_dict() if analysis_cache else None

    return jsonify(result)


@api_bp.route('/shared/<share_id>', methods=['DELETE'])
def delete_shared_link(share_id):
    """Delete a shared link."""
    shared = SharedAnalysis.query.filter_by(share_id=share_id).first_or_404()
    db.session.delete(shared)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Shared link deleted'})


@api_bp.route('/log-files/<int:file_id>/shared-links', methods=['GET'])
def get_file_shared_links(file_id):
    """Get all shared links for a log file."""
    log_file = LogFile.query.get_or_404(file_id)
    shared_links = SharedAnalysis.query.filter_by(log_file_id=file_id).all()
    return jsonify([s.to_dict() for s in shared_links])


# ============================================
# Jira API Integration Endpoints
# ============================================

@api_bp.route('/jira/config', methods=['GET'])
def get_jira_config():
    """Get Jira configuration (without API token)."""
    config = JiraConfig.query.filter_by(is_active=True).first()
    if not config:
        return jsonify({'configured': False})

    return jsonify({
        'configured': True,
        **config.to_dict()
    })


@api_bp.route('/jira/config', methods=['POST'])
def save_jira_config():
    """Save or update Jira configuration."""
    data = request.get_json()

    required = ['server_url', 'email', 'api_token']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # Deactivate any existing config
    JiraConfig.query.update({'is_active': False})

    config = JiraConfig(
        server_url=data['server_url'].rstrip('/'),
        email=data['email'],
        api_token=data['api_token'],
        project_key=data.get('project_key'),
        default_issue_type=data.get('default_issue_type', 'Bug'),
        is_active=True
    )
    db.session.add(config)
    db.session.commit()

    return jsonify({'success': True, **config.to_dict()})


@api_bp.route('/jira/test', methods=['POST'])
def test_jira_connection():
    """Test Jira API connection."""
    import requests
    from requests.auth import HTTPBasicAuth

    config = JiraConfig.query.filter_by(is_active=True).first()
    if not config:
        return jsonify({'success': False, 'error': 'Jira not configured'}), 400

    try:
        response = requests.get(
            f"{config.server_url}/rest/api/3/myself",
            auth=HTTPBasicAuth(config.email, config.api_token),
            headers={'Accept': 'application/json'},
            timeout=10
        )

        if response.status_code == 200:
            user_data = response.json()
            return jsonify({
                'success': True,
                'user': user_data.get('displayName'),
                'email': user_data.get('emailAddress')
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Jira API returned {response.status_code}: {response.text}'
            }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/jira/projects', methods=['GET'])
def get_jira_projects():
    """Get available Jira projects."""
    import requests
    from requests.auth import HTTPBasicAuth

    config = JiraConfig.query.filter_by(is_active=True).first()
    if not config:
        return jsonify({'error': 'Jira not configured'}), 400

    try:
        response = requests.get(
            f"{config.server_url}/rest/api/3/project/search",
            auth=HTTPBasicAuth(config.email, config.api_token),
            headers={'Accept': 'application/json'},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            projects = [{'key': p['key'], 'name': p['name']} for p in data.get('values', [])]
            return jsonify(projects)
        else:
            return jsonify({'error': f'Failed to fetch projects: {response.status_code}'}), 400

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/jira/create-issue', methods=['POST'])
def create_jira_issue():
    """Create a Jira issue directly via API."""
    import requests
    from requests.auth import HTTPBasicAuth

    config = JiraConfig.query.filter_by(is_active=True).first()
    if not config:
        return jsonify({'error': 'Jira not configured'}), 400

    data = request.get_json()

    if not data.get('summary'):
        return jsonify({'error': 'Summary is required'}), 400

    project_key = data.get('project_key') or config.project_key
    if not project_key:
        return jsonify({'error': 'Project key is required'}), 400

    # Build Jira issue payload
    issue_data = {
        'fields': {
            'project': {'key': project_key},
            'summary': data['summary'],
            'description': {
                'type': 'doc',
                'version': 1,
                'content': [
                    {
                        'type': 'paragraph',
                        'content': [{'type': 'text', 'text': data.get('description', '')}]
                    }
                ]
            },
            'issuetype': {'name': data.get('issue_type') or config.default_issue_type}
        }
    }

    # Add priority if provided
    if data.get('priority'):
        issue_data['fields']['priority'] = {'name': data['priority']}

    # Add labels if provided
    if data.get('labels'):
        issue_data['fields']['labels'] = data['labels']

    try:
        response = requests.post(
            f"{config.server_url}/rest/api/3/issue",
            auth=HTTPBasicAuth(config.email, config.api_token),
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
            json=issue_data,
            timeout=30
        )

        if response.status_code in (200, 201):
            result = response.json()
            issue_key = result.get('key')
            return jsonify({
                'success': True,
                'key': issue_key,
                'url': f"{config.server_url}/browse/{issue_key}"
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Jira API returned {response.status_code}: {response.text}'
            }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Timeline Visualization Endpoint
# ============================================

@api_bp.route('/log-files/<int:file_id>/timeline', methods=['GET'])
def get_issue_timeline(file_id):
    """Get timeline data for issues in a log file."""
    log_file = LogFile.query.get_or_404(file_id)

    # Get all entries with timestamps
    entries = LogEntry.query.filter(
        LogEntry.log_file_id == file_id,
        LogEntry.timestamp.isnot(None)
    ).order_by(LogEntry.timestamp).all()

    if not entries:
        return jsonify({'error': 'No timestamped entries found'}), 404

    # Get issues
    issues = Issue.query.filter_by(log_file_id=file_id).all()

    # Build timeline events
    events = []

    # Add error/warning entries as events
    for entry in entries:
        if entry.severity and entry.severity.upper() in ('ERROR', 'CRITICAL', 'FATAL', 'WARNING'):
            events.append({
                'type': 'log_entry',
                'timestamp': entry.timestamp.isoformat(),
                'severity': entry.severity,
                'service': entry.service,
                'message': (entry.message or '')[:100],
                'line_number': entry.line_number
            })

    # Add issues as events
    for issue in issues:
        if issue.first_occurrence:
            events.append({
                'type': 'issue',
                'timestamp': issue.first_occurrence.isoformat(),
                'severity': issue.severity,
                'title': issue.title,
                'category': issue.category,
                'occurrence_count': issue.occurrence_count,
                'issue_id': issue.id
            })

    # Sort by timestamp
    events.sort(key=lambda x: x['timestamp'])

    # Calculate time range
    first_ts = entries[0].timestamp.isoformat() if entries else None
    last_ts = entries[-1].timestamp.isoformat() if entries else None

    return jsonify({
        'events': events,
        'start_time': first_ts,
        'end_time': last_ts,
        'total_events': len(events)
    })


# ============================================
# Multi-File Analysis Endpoint
# ============================================

@api_bp.route('/multi-analysis', methods=['POST'])
def multi_file_analysis():
    """Analyze multiple log files together."""
    from app.services import get_ai_agent

    data = request.get_json()
    file_ids = data.get('file_ids', [])
    query = data.get('query', 'Compare these log files and find common issues.')

    if len(file_ids) < 2:
        return jsonify({'error': 'At least 2 file IDs required'}), 400

    if len(file_ids) > 5:
        return jsonify({'error': 'Maximum 5 files can be analyzed together'}), 400

    # Collect entries from all files
    all_entries = []
    file_info = []

    for file_id in file_ids:
        log_file = LogFile.query.get(file_id)
        if not log_file:
            continue

        entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).limit(200).all()

        file_info.append({
            'id': file_id,
            'filename': log_file.original_filename,
            'total_lines': log_file.total_lines,
            'error_count': log_file.error_count,
            'warning_count': log_file.warning_count
        })

        for entry in entries:
            all_entries.append({
                'file_id': file_id,
                'filename': log_file.original_filename,
                'line_number': entry.line_number,
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'level': entry.severity,
                'service': entry.service,
                'message': entry.message,
                'content': entry.raw_content
            })

    # Get AI agent
    agent = get_ai_agent()
    if not agent.is_available():
        return jsonify({
            'success': False,
            'error': 'AI Agent not available'
        }), 503

    # Perform analysis with context about multiple files
    enhanced_query = f"""
    I have {len(file_info)} log files to analyze together:
    {json.dumps(file_info, indent=2)}

    User's question: {query}

    Please compare these files and:
    1. Find common issues across files
    2. Identify issues unique to each file
    3. Look for patterns or correlations
    4. Highlight any regression or improvements between files
    """

    result = agent.analyze(
        query=enhanced_query,
        log_entries=all_entries,
        session_id=f'multi_{"-".join(map(str, file_ids))}'
    )

    result['files_analyzed'] = file_info
    return jsonify(result)


# ============================================
# Compressed File Support Endpoint
# ============================================

@api_bp.route('/upload/compressed', methods=['POST'])
def upload_compressed_file():
    """Handle compressed log file uploads (.gz, .zip)."""
    import gzip
    import zipfile
    import tempfile
    import shutil

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    filename = file.filename

    if not filename:
        return jsonify({'error': 'No filename'}), 400

    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    extracted_files = []

    try:
        if filename.endswith('.gz'):
            # Handle .gz file
            temp_path = Path(temp_dir) / filename
            file.save(temp_path)

            output_name = filename[:-3]  # Remove .gz extension
            output_path = Path(temp_dir) / output_name

            with gzip.open(temp_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            extracted_files.append((output_path, output_name))

        elif filename.endswith('.zip'):
            # Handle .zip file
            temp_path = Path(temp_dir) / filename
            file.save(temp_path)

            with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                for name in zip_ref.namelist():
                    if name.endswith('.log') or name.endswith('.txt'):
                        zip_ref.extract(name, temp_dir)
                        extracted_files.append((Path(temp_dir) / name, name))
        else:
            return jsonify({'error': 'Unsupported file format. Use .gz or .zip'}), 400

        # Process extracted files
        results = []
        for file_path, original_name in extracted_files:
            # Use existing upload logic
            from werkzeug.datastructures import FileStorage

            with open(file_path, 'rb') as f:
                # Create a FileStorage-like object
                storage = FileStorage(
                    stream=f,
                    filename=original_name,
                    content_type='text/plain'
                )

                # Save to uploads folder
                from uuid import uuid4
                saved_filename = f"{uuid4().hex}_{original_name}"
                upload_path = current_app.config['UPLOAD_FOLDER'] / saved_filename

                with open(upload_path, 'wb') as dest:
                    dest.write(f.read())

                # Parse the file
                f.seek(0)
                parser = LogParser()
                entries, stats = parser.parse_file_full(upload_path)

                # Create database record
                log_file = LogFile(
                    filename=saved_filename,
                    original_filename=original_name,
                    file_size=file_path.stat().st_size,
                    total_lines=stats.get('total_lines', len(entries)),
                    error_count=stats.get('error_count', 0) + stats.get('critical_count', 0),
                    warning_count=stats.get('warning_count', 0),
                    parsed=True
                )
                db.session.add(log_file)
                db.session.commit()

                # Save entries
                for entry_data in entries:
                    entry = LogEntry(
                        log_file_id=log_file.id,
                        line_number=entry_data.get('line_number'),
                        timestamp=entry_data.get('timestamp'),
                        severity=entry_data.get('severity'),
                        service=entry_data.get('service'),
                        component=entry_data.get('component'),
                        command=entry_data.get('command'),
                        message=entry_data.get('message'),
                        raw_content=entry_data.get('raw_content')
                    )
                    db.session.add(entry)

                db.session.commit()

                results.append({
                    'id': log_file.id,
                    'filename': original_name,
                    'lines': log_file.total_lines,
                    'errors': log_file.error_count,
                    'warnings': log_file.warning_count
                })

        return jsonify({
            'success': True,
            'files_extracted': len(results),
            'files': results
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================
# PDF Export Endpoint
# ============================================

@api_bp.route('/log-files/<int:file_id>/export/pdf', methods=['GET'])
def export_log_pdf(file_id):
    """Export log file analysis as PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        import io
    except ImportError:
        return jsonify({'error': 'PDF export requires reportlab. Install with: pip install reportlab'}), 503

    log_file = LogFile.query.get_or_404(file_id)
    entries = LogEntry.query.filter_by(log_file_id=file_id).order_by(LogEntry.line_number).all()
    issues = Issue.query.filter_by(log_file_id=file_id).all()

    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=20)
    elements.append(Paragraph(f"Log Analysis Report: {log_file.original_filename}", title_style))
    elements.append(Spacer(1, 12))

    # Summary
    elements.append(Paragraph("Summary", styles['Heading2']))
    summary_data = [
        ['Total Lines', str(log_file.total_lines)],
        ['Errors', str(log_file.error_count)],
        ['Warnings', str(log_file.warning_count)],
        ['Issues Detected', str(len(issues))],
        ['Upload Date', log_file.upload_date.strftime('%Y-%m-%d %H:%M') if log_file.upload_date else 'N/A']
    ]

    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Issues
    if issues:
        elements.append(Paragraph("Detected Issues", styles['Heading2']))
        for issue in issues:
            issue_style = ParagraphStyle('Issue', parent=styles['Normal'], fontSize=10, leftIndent=20)
            severity_colors = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'blue'}
            color = severity_colors.get(issue.severity, 'black')

            elements.append(Paragraph(f"<font color='{color}'><b>[{issue.severity}]</b></font> {issue.title}", styles['Normal']))
            if issue.description:
                elements.append(Paragraph(issue.description[:200], issue_style))
            elements.append(Spacer(1, 10))

    # Build PDF
    doc.build(elements)
    buffer.seek(0)

    from flask import Response
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename={log_file.original_filename}_report.pdf'}
    )


# ============================================
# Live Log Streaming Endpoints
# ============================================

@api_bp.route('/log-files/<int:file_id>/stream', methods=['GET'])
def stream_log_file(file_id):
    """
    Stream log file updates using Server-Sent Events (SSE).
    Watches for new entries added to the log file.
    """
    from flask import Response, stream_with_context
    import time

    log_file = LogFile.query.get_or_404(file_id)
    last_line = request.args.get('last_line', 0, type=int)

    def generate():
        nonlocal last_line
        while True:
            # Get new entries since last_line
            new_entries = LogEntry.query.filter(
                LogEntry.log_file_id == file_id,
                LogEntry.line_number > last_line
            ).order_by(LogEntry.line_number).limit(100).all()

            if new_entries:
                last_line = new_entries[-1].line_number
                data = {
                    'entries': [e.to_dict() for e in new_entries],
                    'last_line': last_line
                }
                yield f"data: {json.dumps(data)}\n\n"

            # Send heartbeat every 30 seconds
            yield f": heartbeat\n\n"
            time.sleep(2)  # Poll every 2 seconds

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


def get_fw_password_from_aws():
    """
    Get the firmware password from AWS SSM Parameter Store.
    Returns the password or None if unable to retrieve.
    """
    import subprocess
    import os

    try:
        env = os.environ.copy()
        env['AWS_PROFILE'] = 'fw-ops'

        cmd = [
            'aws', 'ssm', 'get-parameter',
            '--name', '/lockness/grant/fw-developer/prod/fw-password/key',
            '--with-decryption',
            '--region', 'us-west-1',
            '--query', 'Parameter.Value',
            '--output', 'text'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


# Cache the AWS password
_cached_fw_password = None

def get_cached_fw_password():
    """Get cached firmware password, fetching from AWS if needed."""
    global _cached_fw_password
    if _cached_fw_password is None:
        _cached_fw_password = get_fw_password_from_aws()
    return _cached_fw_password


def ssh_connect_with_fallback(host, port, username, password, timeout=10):
    """
    Try to connect via SSH using multiple methods:
    1. Empty password (none auth - common for cameras)
    2. SSH key (from default locations)
    3. Password authentication (user-provided or AWS SSM)
    Returns (client, auth_method) or raises exception
    """
    import paramiko
    import subprocess
    from pathlib import Path

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 1. Try empty password first (none auth - cameras often use this)
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password='',
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )
        return client, "none_auth"
    except paramiko.AuthenticationException:
        pass
    except paramiko.SSHException:
        pass

    # 2. Try SSH key authentication
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            timeout=timeout,
            look_for_keys=True,
            allow_agent=True
        )
        return client, "ssh_key"
    except paramiko.AuthenticationException:
        pass
    except paramiko.SSHException:
        pass

    # 3. Try AWS firmware password
    fw_password = get_cached_fw_password()
    if fw_password:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=fw_password,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )
            return client, "aws_ssm"
        except paramiko.AuthenticationException:
            pass
        except paramiko.SSHException:
            pass

    # 4. Try user-provided password
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        look_for_keys=False,
        allow_agent=False
    )
    return client, "password"


@api_bp.route('/stream/test-connection', methods=['POST'])
def test_ssh_connection():
    """
    Test SSH connection to camera without streaming.
    """
    import paramiko

    data = request.get_json() or {}
    host = data.get('host', '192.168.50.1')
    username = data.get('username', 'root')
    password = data.get('password', 'root')
    port = data.get('port', 22)

    try:
        client, auth_method = ssh_connect_with_fallback(host, port, username, password, timeout=5)

        # Try to run a simple command
        stdin, stdout, stderr = client.exec_command('echo "connected"', timeout=5)
        result = stdout.read().decode().strip()
        client.close()

        return jsonify({
            'success': True,
            'message': f'Successfully connected to {host}:{port} (via {auth_method})'
        })
    except paramiko.AuthenticationException:
        return jsonify({
            'success': False,
            'message': f'Authentication failed. Check username/password for {host} or ensure SSH key is configured.'
        })
    except paramiko.SSHException as e:
        return jsonify({
            'success': False,
            'message': f'SSH error: {str(e)}'
        })
    except Exception as e:
        error_msg = str(e)
        if 'Connection refused' in error_msg:
            error_msg = f'Connection refused. Is SSH enabled on {host}:{port}?'
        elif 'timed out' in error_msg.lower() or 'timeout' in error_msg.lower():
            error_msg = f'Connection timed out. Check if camera is reachable at {host}'
        elif 'Connection reset' in error_msg:
            error_msg = f'Connection reset. Camera at {host} may not be running SSH'
        return jsonify({
            'success': False,
            'message': error_msg
        })


@api_bp.route('/stream/camera', methods=['GET'])
def stream_camera_logs():
    """
    Stream live output from camera via SSH using Server-Sent Events.
    Query params: host, username, password, port, command (or log_path for backward compat)
    """
    from flask import Response, stream_with_context
    import time

    host = request.args.get('host', '192.168.50.1')
    username = request.args.get('username', 'root')
    password = request.args.get('password', '')
    port = request.args.get('port', 22, type=int)

    # Support custom command or fall back to tail on log_path
    command = request.args.get('command', '')
    if not command:
        log_path = request.args.get('log_path', '/var/log/messages')
        lines = request.args.get('lines', 50, type=int)
        command = f'tail -n {lines} -f {log_path}'

    def generate():
        try:
            import paramiko
            import select

            # Connect via SSH (try key first, then password)
            client, auth_method = ssh_connect_with_fallback(host, port, username, password, timeout=10)

            # Start the command
            transport = client.get_transport()
            channel = transport.open_session()
            channel.get_pty()  # Get pseudo-terminal for interactive commands
            channel.exec_command(command)

            # Send initial connection success
            yield f"data: {json.dumps({'type': 'connected', 'host': host, 'command': command})}\n\n"

            # Stream output
            while True:
                if channel.recv_ready():
                    data = channel.recv(4096).decode('utf-8', errors='replace')
                    lines_data = data.strip().split('\n')
                    for line in lines_data:
                        if line:
                            yield f"data: {json.dumps({'type': 'log', 'content': line})}\n\n"

                if channel.exit_status_ready():
                    break

                # Check for client disconnect
                time.sleep(0.1)

            client.close()
            yield f"data: {json.dumps({'type': 'disconnected'})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@api_bp.route('/log-files/<int:file_id>/tail', methods=['GET'])
def tail_log_file(file_id):
    """
    Get the last N lines of a log file (for polling-based tail).
    """
    log_file = LogFile.query.get_or_404(file_id)
    lines = request.args.get('lines', 50, type=int)
    lines = min(lines, 500)  # Cap at 500

    entries = LogEntry.query.filter_by(log_file_id=file_id)\
        .order_by(LogEntry.line_number.desc())\
        .limit(lines)\
        .all()

    # Reverse to get chronological order
    entries = list(reversed(entries))

    return jsonify({
        'entries': [e.to_dict() for e in entries],
        'total_lines': log_file.total_lines,
        'last_line': entries[-1].line_number if entries else 0
    })


@api_bp.route('/log-files/<int:file_id>/new-entries', methods=['GET'])
def get_new_entries(file_id):
    """
    Get entries newer than a specific line number (for polling-based updates).
    """
    log_file = LogFile.query.get_or_404(file_id)
    after_line = request.args.get('after', 0, type=int)
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 500)

    entries = LogEntry.query.filter(
        LogEntry.log_file_id == file_id,
        LogEntry.line_number > after_line
    ).order_by(LogEntry.line_number).limit(limit).all()

    return jsonify({
        'entries': [e.to_dict() for e in entries],
        'count': len(entries),
        'last_line': entries[-1].line_number if entries else after_line,
        'has_more': len(entries) == limit
    })
