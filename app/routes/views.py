"""
View routes - Renders HTML templates for the web UI
"""
import json
import os
from datetime import datetime

from flask import render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename

from app import db
from app.models import LogFile, LogEntry, Issue, BugReport
from app.routes import main_bp
from app.services import (
    LogParser, IssueDetector, BugReportGenerator,
    CameraDownloader, get_s3_downloader
)


def allowed_file(filename):
    """Check if file extension is allowed"""
    allowed = current_app.config.get('ALLOWED_EXTENSIONS')
    # If ALLOWED_EXTENSIONS is None, allow all files
    if allowed is None:
        return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


@main_bp.route('/')
def index():
    """Main dashboard page"""
    log_files = LogFile.query.order_by(LogFile.upload_date.desc()).all()

    # Calculate overall statistics
    total_errors = sum(f.error_count for f in log_files)
    total_warnings = sum(f.warning_count for f in log_files)
    total_issues = Issue.query.count()
    critical_issues = Issue.query.filter_by(severity='CRITICAL').count()

    return render_template('index.html',
                           log_files=log_files,
                           total_errors=total_errors,
                           total_warnings=total_warnings,
                           total_issues=total_issues,
                           critical_issues=critical_issues)


@main_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Generate unique filename
            upload_folder = current_app.config['UPLOAD_FOLDER']
            base, ext = os.path.splitext(filename)
            counter = 1
            unique_filename = filename
            while (upload_folder / unique_filename).exists():
                unique_filename = f"{base}_{counter}{ext}"
                counter += 1

            file_path = upload_folder / unique_filename
            file.save(file_path)

            # Get file size
            file_size = file_path.stat().st_size

            # Create database record
            log_file = LogFile(
                filename=unique_filename,
                original_filename=filename,
                file_size=file_size
            )
            db.session.add(log_file)
            db.session.commit()

            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('main.view_log', file_id=log_file.id))
        else:
            flash('File type not allowed. Please upload .log or .txt files.', 'error')
            return redirect(request.url)

    return render_template('upload.html')


@main_bp.route('/paste-log', methods=['POST'])
def paste_log():
    """Handle pasted log content"""
    log_name = request.form.get('log_name', 'pasted_log').strip()
    log_content = request.form.get('log_content', '').strip()

    if not log_content:
        flash('No log content provided', 'error')
        return redirect(url_for('main.upload'))

    # Sanitize filename
    filename = secure_filename(log_name) or 'pasted_log'
    if not filename.endswith('.log'):
        filename += '.log'

    # Generate unique filename
    upload_folder = current_app.config['UPLOAD_FOLDER']
    base, ext = os.path.splitext(filename)
    counter = 1
    unique_filename = filename
    while (upload_folder / unique_filename).exists():
        unique_filename = f"{base}_{counter}{ext}"
        counter += 1

    # Save pasted content to file
    file_path = upload_folder / unique_filename
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(log_content)

    # Get file size
    file_size = file_path.stat().st_size

    # Create database record
    log_file = LogFile(
        filename=unique_filename,
        original_filename=filename,
        file_size=file_size
    )
    db.session.add(log_file)
    db.session.commit()

    flash(f'Log "{filename}" created successfully!', 'success')
    return redirect(url_for('main.view_log', file_id=log_file.id))


@main_bp.route('/camera-download', methods=['GET', 'POST'])
def camera_download():
    """Download log from camera via SSH"""
    # Get default values from config
    default_ip = current_app.config.get('CAMERA_DEFAULT_IP', '192.168.50.1')
    default_user = current_app.config.get('CAMERA_DEFAULT_USER', 'root')
    default_password = current_app.config.get('CAMERA_DEFAULT_PASSWORD', 'root')
    default_log_path = current_app.config.get('CAMERA_LOG_PATH', '/var/log/messages')
    default_port = current_app.config.get('CAMERA_SSH_PORT', 22)
    default_timeout = current_app.config.get('CAMERA_SSH_TIMEOUT', 30)

    if request.method == 'POST':
        # Get form values
        camera_ip = request.form.get('camera_ip', default_ip).strip()
        username = request.form.get('username', default_user).strip()
        password = request.form.get('password', default_password)
        log_path = request.form.get('log_path', default_log_path).strip()
        port = int(request.form.get('port', default_port))

        # Create downloader and connect
        downloader = CameraDownloader(
            host=camera_ip,
            username=username,
            password=password,
            port=port,
            timeout=default_timeout
        )

        # Download the log file
        result, message = downloader.download_log(log_path)
        downloader.disconnect()

        if result is None:
            flash(f'Download failed: {message}', 'error')
            return redirect(url_for('main.camera_download'))

        # Save the downloaded file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"camera_{result['filename']}_{timestamp}.log"
        unique_filename = secure_filename(filename)

        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_path = upload_folder / unique_filename

        # Write content to file
        with open(file_path, 'wb') as f:
            f.write(result['content'].read())

        file_size = file_path.stat().st_size

        # Create database record
        log_file = LogFile(
            filename=unique_filename,
            original_filename=f"Camera: {log_path}",
            file_size=file_size,
            device_info=json.dumps({
                'source': 'camera',
                'camera_ip': camera_ip,
                'remote_path': log_path,
                'downloaded_at': result['downloaded_at']
            })
        )
        db.session.add(log_file)
        db.session.commit()

        flash(f'Log downloaded from camera successfully! ({file_size / 1024:.1f} KB)', 'success')
        return redirect(url_for('main.view_log', file_id=log_file.id))

    return render_template('camera_download.html',
                           default_ip=default_ip,
                           default_user=default_user,
                           default_password=default_password,
                           default_log_path=default_log_path,
                           default_port=default_port)


@main_bp.route('/camera-test', methods=['POST'])
def camera_test():
    """Test camera connection"""
    camera_ip = request.form.get('camera_ip', '').strip()
    username = request.form.get('username', 'root').strip()
    password = request.form.get('password', 'root')
    port = int(request.form.get('port', 22))

    downloader = CameraDownloader(
        host=camera_ip,
        username=username,
        password=password,
        port=port,
        timeout=10
    )

    success, message = downloader.test_connection()
    downloader.disconnect()

    from flask import jsonify
    return jsonify({
        'success': success,
        'message': message
    })


@main_bp.route('/camera-info', methods=['POST'])
def camera_info():
    """Get camera system info"""
    camera_ip = request.form.get('camera_ip', '').strip()
    username = request.form.get('username', 'root').strip()
    password = request.form.get('password', 'root')
    port = int(request.form.get('port', 22))

    downloader = CameraDownloader(
        host=camera_ip,
        username=username,
        password=password,
        port=port,
        timeout=15
    )

    info, message = downloader.get_camera_info()
    downloader.disconnect()

    from flask import jsonify
    if info:
        return jsonify({
            'success': True,
            'info': info
        })
    else:
        return jsonify({
            'success': False,
            'message': message
        })


@main_bp.route('/camera-list-logs', methods=['POST'])
def camera_list_logs():
    """List available log files on camera"""
    camera_ip = request.form.get('camera_ip', '').strip()
    username = request.form.get('username', 'root').strip()
    password = request.form.get('password', 'root')
    port = int(request.form.get('port', 22))
    directory = request.form.get('directory', '/var/log')

    downloader = CameraDownloader(
        host=camera_ip,
        username=username,
        password=password,
        port=port,
        timeout=15
    )

    files, message = downloader.list_log_files(directory)
    downloader.disconnect()

    from flask import jsonify
    if files is not None:
        return jsonify({
            'success': True,
            'files': files
        })
    else:
        return jsonify({
            'success': False,
            'message': message
        })


# ============================================================================
# S3 Log Download Routes (NexarOne)
# ============================================================================

@main_bp.route('/s3-download', methods=['GET', 'POST'])
def s3_download():
    """Download logs from S3 bucket by serial number"""
    from flask import jsonify

    s3 = get_s3_downloader()
    s3_status = s3.get_status()

    if request.method == 'POST':
        serial_number = request.form.get('serial_number', '').strip()
        date = request.form.get('date', '').strip() or None
        selected_file = request.form.get('selected_file', '').strip()

        if not serial_number:
            flash('Serial number is required', 'error')
            return redirect(url_for('main.s3_download'))

        if not s3_status['available']:
            flash(f"S3 not available: {s3_status['message']}", 'error')
            return redirect(url_for('main.s3_download'))

        try:
            # Download specific file or first file matching date
            content, metadata = s3.download_log(
                serial_number=serial_number,
                filename=selected_file if selected_file else None,
                date=date,
                decompress=True
            )

            # Save to uploads folder
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_name = metadata.get('filename', 'log.txt')
            filename = f"s3_{serial_number}_{original_name}_{timestamp}"
            unique_filename = secure_filename(filename)
            if not unique_filename.endswith('.log'):
                unique_filename += '.log'

            upload_folder = current_app.config['UPLOAD_FOLDER']
            file_path = upload_folder / unique_filename

            # Write content to file
            with open(file_path, 'wb') as f:
                f.write(content.read())

            file_size = file_path.stat().st_size

            # Create database record
            log_file = LogFile(
                filename=unique_filename,
                original_filename=f"S3: {serial_number}/{original_name}",
                file_size=file_size,
                device_info=json.dumps({
                    'source': 's3',
                    'bucket': s3.bucket,
                    's3_key': metadata.get('key'),
                    'serial_number': serial_number,
                    'downloaded_at': datetime.now().isoformat(),
                    'decompressed': metadata.get('decompressed', False)
                })
            )
            db.session.add(log_file)
            db.session.commit()

            flash(f'Log downloaded from S3 successfully! ({file_size / 1024:.1f} KB)', 'success')
            return redirect(url_for('main.view_log', file_id=log_file.id))

        except Exception as e:
            flash(f'S3 download failed: {str(e)}', 'error')
            return redirect(url_for('main.s3_download'))

    return render_template('s3_download.html', s3_status=s3_status)


@main_bp.route('/s3-download-stream', methods=['POST'])
def s3_download_stream():
    """Stream download from S3 with progress support"""
    from flask import jsonify, Response, stream_with_context

    s3 = get_s3_downloader()
    s3_status = s3.get_status()

    serial_number = request.form.get('serial_number', '').strip()
    selected_file = request.form.get('selected_file', '').strip()

    if not serial_number or not selected_file:
        return jsonify({'error': 'Missing parameters'}), 400

    if not s3_status['available']:
        return jsonify({'error': f"S3 not available: {s3_status['message']}"}), 503

    try:
        # Download with decompression
        content, metadata = s3.download_log(
            serial_number=serial_number,
            filename=selected_file,
            decompress=True
        )

        # Get total size
        content_data = content.read()
        total_size = len(content_data)

        # Save to uploads folder and create database record
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_name = metadata.get('filename', 'log.txt')
        filename = f"s3_{serial_number}_{original_name}_{timestamp}"
        unique_filename = secure_filename(filename)
        if not unique_filename.endswith('.log'):
            unique_filename += '.log'

        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_path = upload_folder / unique_filename

        # Write content to file
        with open(file_path, 'wb') as f:
            f.write(content_data)

        file_size = file_path.stat().st_size

        # Create database record
        log_file = LogFile(
            filename=unique_filename,
            original_filename=f"S3: {serial_number}/{original_name}",
            file_size=file_size,
            upload_date=datetime.utcnow(),
            device_info=json.dumps({'source': 's3', 'serial_number': serial_number})
        )
        db.session.add(log_file)
        db.session.commit()

        # Stream the content back
        def generate():
            chunk_size = 8192
            for i in range(0, len(content_data), chunk_size):
                yield content_data[i:i + chunk_size]

        response = Response(
            stream_with_context(generate()),
            mimetype='application/octet-stream'
        )
        response.headers['Content-Disposition'] = f'attachment; filename="{unique_filename}"'
        response.headers['Content-Length'] = str(total_size)
        response.headers['X-Total-Size'] = str(total_size)
        response.headers['X-File-Id'] = str(log_file.id)

        return response

    except Exception as e:
        import traceback
        print(f"S3 download error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@main_bp.route('/s3-list-logs', methods=['POST'])
def s3_list_logs():
    """List available logs for a serial number"""
    from flask import jsonify
    from datetime import datetime, timedelta

    serial_number = request.form.get('serial_number', '').strip()
    date = request.form.get('date', '').strip() or None
    days_back = int(request.form.get('days_back', 0) or 0)

    if not serial_number:
        return jsonify({'success': False, 'message': 'Serial number is required'})

    try:
        s3 = get_s3_downloader()
        # Get more files to allow filtering (increased limit for full coverage)
        files = s3.list_logs(serial_number, date=date, limit=5000)

        # Filter by date range if specified
        # Use folder date (from S3 key path) rather than last_modified,
        # because folder date represents when the log was created on the camera
        if days_back > 0:
            cutoff_date = datetime.now() - timedelta(days=days_back)
            filtered_files = []
            for f in files:
                try:
                    # Parse date from folder name (format: YYYY-MM-DD_HH-MM)
                    folder = f.get('folder', '')
                    if folder and len(folder) >= 10:
                        folder_date = datetime.strptime(folder[:10], '%Y-%m-%d')
                        if folder_date >= cutoff_date:
                            filtered_files.append(f)
                    else:
                        # Fallback to last_modified if no folder date
                        file_date = datetime.fromisoformat(f['last_modified'].replace('Z', '+00:00'))
                        if file_date.replace(tzinfo=None) >= cutoff_date:
                            filtered_files.append(f)
                except (ValueError, KeyError):
                    # If we can't parse the date, include it anyway
                    filtered_files.append(f)
            files = filtered_files

        return jsonify({
            'success': True,
            'files': files,
            'count': len(files)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main_bp.route('/s3-list-dates', methods=['POST'])
def s3_list_dates():
    """List available dates for a serial number"""
    from flask import jsonify

    serial_number = request.form.get('serial_number', '').strip()

    if not serial_number:
        return jsonify({'success': False, 'message': 'Serial number is required'})

    try:
        s3 = get_s3_downloader()
        dates = s3.get_log_dates(serial_number)
        return jsonify({
            'success': True,
            'dates': dates,
            'count': len(dates)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@main_bp.route('/s3-status', methods=['GET'])
def s3_status():
    """Check S3 connection status"""
    from flask import jsonify

    s3 = get_s3_downloader()
    return jsonify(s3.get_status())


@main_bp.route('/s3-set-profile', methods=['POST'])
def s3_set_profile():
    """Switch AWS profile for S3 access"""
    from flask import jsonify
    from app.services.s3_downloader import reset_s3_downloader

    profile = request.form.get('profile', '').strip()
    if not profile:
        return jsonify({'success': False, 'message': 'Profile name is required'})

    # Reset and reinitialize with new profile
    reset_s3_downloader()
    s3 = get_s3_downloader(profile=profile)

    status = s3.get_status()
    return jsonify({
        'success': status['available'],
        'message': status['message'],
        'profile': profile
    })


@main_bp.route('/s3-refresh', methods=['POST'])
def s3_refresh():
    """Refresh S3 connection (re-check credentials)"""
    from flask import jsonify
    from app.services.s3_downloader import reset_s3_downloader

    reset_s3_downloader()
    s3 = get_s3_downloader()
    return jsonify(s3.get_status())


@main_bp.route('/log/<int:file_id>')
def view_log(file_id):
    """View log entries with filtering and search modes"""
    log_file = LogFile.query.get_or_404(file_id)
    file_path = current_app.config['UPLOAD_FOLDER'] / log_file.filename

    # Parse file if not already parsed
    if not log_file.parsed and file_path.exists():
        parser = LogParser()
        entries, stats = parser.parse_file_full(file_path)

        # Get device info
        device_info = parser.get_device_info(file_path)
        log_file.device_info = json.dumps(device_info)

        # Save entries to database
        for entry_data in entries:
            entry = LogEntry(
                log_file_id=log_file.id,
                line_number=entry_data['line_number'],
                timestamp=entry_data['timestamp'],
                severity=entry_data['severity'],
                service=entry_data['service'],
                component=entry_data['component'],
                command=entry_data['command'],
                message=entry_data['message'],
                raw_content=entry_data['raw_content']
            )
            db.session.add(entry)

        # Update log file stats
        log_file.total_lines = stats['total_lines']
        log_file.error_count = stats['error_count'] + stats.get('critical_count', 0)
        log_file.warning_count = stats['warning_count']
        log_file.info_count = stats['info_count']
        log_file.parsed = True

        db.session.commit()

    # Get filter parameters
    severity = request.args.get('severity')
    service = request.args.get('service')
    component = request.args.get('component')
    search = request.args.get('search', '')
    search_mode = request.args.get('search_mode', 'contains')  # contains, regex, exact
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)

    # Allow unlimited (99999 means all)
    if per_page >= 99999:
        per_page = 100000  # Effectively unlimited

    # Build query
    query = LogEntry.query.filter_by(log_file_id=file_id)

    if severity:
        query = query.filter_by(severity=severity)
    if service:
        query = query.filter_by(service=service)
    if component:
        query = query.filter_by(component=component)

    # Apply search based on mode
    if search:
        if search_mode == 'exact':
            # Case-sensitive exact match
            query = query.filter(LogEntry.raw_content.contains(search))
        elif search_mode == 'regex':
            # Regex search - use SQLite's REGEXP if available, otherwise fallback
            try:
                query = query.filter(LogEntry.raw_content.op('REGEXP')(search))
            except Exception:
                # Fallback to case-insensitive contains if REGEXP not supported
                query = query.filter(LogEntry.raw_content.ilike(f'%{search}%'))
        else:
            # Default: case-insensitive contains
            query = query.filter(LogEntry.raw_content.ilike(f'%{search}%'))

    # Paginate
    entries = query.order_by(LogEntry.line_number).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get filter options
    services = db.session.query(LogEntry.service).filter_by(log_file_id=file_id).distinct().all()
    services = [s[0] for s in services if s[0]]

    components = db.session.query(LogEntry.component).filter_by(log_file_id=file_id).distinct().all()
    components = [c[0] for c in components if c[0]]

    severities = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']

    return render_template('log_viewer.html',
                           log_file=log_file,
                           entries=entries,
                           services=services,
                           components=components,
                           severities=severities,
                           current_severity=severity,
                           current_service=service,
                           current_component=component,
                           search=search,
                           search_mode=search_mode)


@main_bp.route('/compare')
def compare():
    """Compare two log files"""
    log_files = LogFile.query.order_by(LogFile.upload_date.desc()).all()
    return render_template('compare.html', log_files=log_files)


@main_bp.route('/live')
def live_stream():
    """Live log streaming page"""
    log_files = LogFile.query.order_by(LogFile.upload_date.desc()).all()
    return render_template('live_stream.html', log_files=log_files)


@main_bp.route('/dashboard')
def dashboard():
    """Multi-camera dashboard with error rates"""
    from datetime import timedelta
    from collections import defaultdict

    # Get time range filter
    time_range = request.args.get('range', '24h')
    now = datetime.now()

    if time_range == '1h':
        cutoff = now - timedelta(hours=1)
    elif time_range == '6h':
        cutoff = now - timedelta(hours=6)
    elif time_range == '7d':
        cutoff = now - timedelta(days=7)
    elif time_range == 'all':
        cutoff = None
    else:  # 24h default
        cutoff = now - timedelta(hours=24)

    # Get all log files
    query = LogFile.query
    if cutoff:
        query = query.filter(LogFile.upload_date >= cutoff)
    log_files = query.order_by(LogFile.upload_date.desc()).all()

    # Group logs by camera/device
    cameras_dict = defaultdict(lambda: {
        'name': 'Unknown',
        'logs': [],
        'error_count': 0,
        'warning_count': 0,
        'log_count': 0
    })

    for log_file in log_files:
        # Extract camera/device identifier from filename or device_info
        device_name = 'Unknown'
        device_info = json.loads(log_file.device_info) if log_file.device_info else {}

        if device_info.get('source') == 'camera':
            device_name = f"Camera ({device_info.get('camera_ip', 'Unknown')})"
        elif device_info.get('source') == 's3':
            device_name = f"S3 ({device_info.get('serial_number', 'Unknown')})"
        elif 'camera' in log_file.original_filename.lower():
            # Try to extract from filename
            device_name = log_file.original_filename.split('_')[0] if '_' in log_file.original_filename else 'Camera'
        else:
            device_name = 'Local Upload'

        cameras_dict[device_name]['name'] = device_name
        cameras_dict[device_name]['logs'].append(log_file)
        cameras_dict[device_name]['error_count'] += log_file.error_count
        cameras_dict[device_name]['warning_count'] += log_file.warning_count
        cameras_dict[device_name]['log_count'] += 1

    # Convert to list with additional computed fields
    cameras = []
    for idx, (name, data) in enumerate(cameras_dict.items()):
        # Determine status based on error rate
        if data['error_count'] > 10:
            status = 'critical'
        elif data['error_count'] > 0 or data['warning_count'] > 10:
            status = 'warning'
        else:
            status = 'healthy'

        cameras.append({
            'id': idx + 1,
            'name': name,
            'log_count': data['log_count'],
            'error_count': data['error_count'],
            'warning_count': data['warning_count'],
            'status': status,
            'recent_logs': sorted(data['logs'], key=lambda x: x.upload_date or datetime.min, reverse=True)[:5]
        })

    # Sort cameras by error count (most errors first)
    cameras.sort(key=lambda x: x['error_count'], reverse=True)

    # Calculate totals
    total_logs = len(log_files)
    total_errors = sum(f.error_count for f in log_files)
    total_warnings = sum(f.warning_count for f in log_files)
    healthy_cameras = len([c for c in cameras if c['status'] == 'healthy'])

    # Build error rate chart data (errors over time)
    # Group by hour
    error_rate_data = {'labels': [], 'errors': [], 'warnings': []}
    time_buckets = defaultdict(lambda: {'errors': 0, 'warnings': 0})

    for log_file in log_files:
        if log_file.upload_date:
            bucket = log_file.upload_date.strftime('%m/%d %H:00')
            time_buckets[bucket]['errors'] += log_file.error_count
            time_buckets[bucket]['warnings'] += log_file.warning_count

    # Sort by time and take last 24 buckets
    sorted_buckets = sorted(time_buckets.items())[-24:]
    for bucket, data in sorted_buckets:
        error_rate_data['labels'].append(bucket)
        error_rate_data['errors'].append(data['errors'])
        error_rate_data['warnings'].append(data['warnings'])

    # Mini chart data for each camera
    camera_chart_data = {}
    for camera in cameras:
        chart_data = {'labels': [], 'errors': []}
        for log in camera['recent_logs'][:10]:
            if log.upload_date:
                chart_data['labels'].append(log.upload_date.strftime('%H:%M'))
                chart_data['errors'].append(log.error_count)
        # Reverse to show chronological order
        chart_data['labels'].reverse()
        chart_data['errors'].reverse()
        camera_chart_data[camera['id']] = chart_data

    # Get recent errors from log entries
    recent_errors = []
    if cutoff:
        error_entries = LogEntry.query.filter(
            LogEntry.severity.in_(['ERROR', 'CRITICAL'])
        ).order_by(LogEntry.timestamp.desc()).limit(50).all()
    else:
        error_entries = LogEntry.query.filter(
            LogEntry.severity.in_(['ERROR', 'CRITICAL'])
        ).order_by(LogEntry.id.desc()).limit(50).all()

    for entry in error_entries:
        log_file = LogFile.query.get(entry.log_file_id)
        device_info = json.loads(log_file.device_info) if log_file and log_file.device_info else {}
        device_name = device_info.get('serial_number') or device_info.get('camera_ip') or 'Unknown'

        recent_errors.append({
            'timestamp': entry.timestamp,
            'device': device_name,
            'message': entry.message or entry.raw_content[:100],
            'log_file_id': entry.log_file_id,
            'line_number': entry.line_number
        })

    return render_template('dashboard.html',
                           cameras=cameras,
                           total_logs=total_logs,
                           total_errors=total_errors,
                           total_warnings=total_warnings,
                           healthy_cameras=healthy_cameras,
                           error_rate_data=error_rate_data,
                           camera_chart_data=camera_chart_data,
                           recent_errors=recent_errors,
                           current_range=time_range)


@main_bp.route('/issues')
def issues_list():
    """List all issues across all log files"""
    severity = request.args.get('severity')
    status = request.args.get('status', 'open')

    query = Issue.query

    if severity:
        query = query.filter_by(severity=severity)
    if status and status != 'all':
        query = query.filter_by(status=status)

    issues = query.order_by(Issue.created_at.desc()).all()

    return render_template('issues.html',
                           issues=issues,
                           current_severity=severity,
                           current_status=status)


@main_bp.route('/issue/<int:issue_id>')
def issue_detail(issue_id):
    """View issue details"""
    issue = Issue.query.get_or_404(issue_id)
    log_file = issue.log_file

    # Get context entries
    affected_lines = json.loads(issue.affected_lines) if issue.affected_lines else []
    context_entries = []

    if affected_lines:
        first_line = min(affected_lines)
        last_line = max(affected_lines)
        context_entries = LogEntry.query.filter(
            LogEntry.log_file_id == log_file.id,
            LogEntry.line_number >= first_line - 5,
            LogEntry.line_number <= last_line + 5
        ).order_by(LogEntry.line_number).all()

    # Extract enhanced data from context JSON
    explanation = ''
    why_it_matters = ''
    suggested_actions = []
    technical_details = ''

    try:
        context_data = json.loads(issue.context) if issue.context else {}
        if isinstance(context_data, dict) and 'enhanced' in context_data:
            explanation = context_data['enhanced'].get('explanation', '')
            why_it_matters = context_data['enhanced'].get('why_it_matters', '')
            suggested_actions = context_data['enhanced'].get('suggested_actions', [])
            technical_details = context_data['enhanced'].get('technical_details', '')
    except (json.JSONDecodeError, TypeError):
        pass

    return render_template('issue_detail.html',
                           issue=issue,
                           log_file=log_file,
                           context_entries=context_entries,
                           affected_lines=affected_lines,
                           explanation=explanation,
                           why_it_matters=why_it_matters,
                           suggested_actions=suggested_actions,
                           technical_details=technical_details)


@main_bp.route('/bug-report/create/<int:issue_id>', methods=['GET', 'POST'])
def create_bug_report(issue_id):
    """Create a bug report from an issue"""
    issue = Issue.query.get_or_404(issue_id)
    log_file = issue.log_file

    if request.method == 'POST':
        generator = BugReportGenerator()

        device_info = json.loads(log_file.device_info) if log_file.device_info else {}
        template = request.form.get('template', 'default')

        report_data = generator.generate_report(
            issue.to_dict(),
            device_info=device_info,
            template_name=template,
            additional_context=request.form.get('additional_context')
        )

        # Create bug report record
        bug_report = BugReport(
            issue_id=issue.id,
            title=report_data['title'],
            description=report_data['description'],
            steps_to_reproduce=request.form.get('steps_to_reproduce', ''),
            expected_behavior=request.form.get('expected_behavior', ''),
            actual_behavior=report_data['actual_behavior'],
            severity=report_data['severity'],
            environment=report_data['environment'],
            log_snippets=report_data['log_snippets']
        )
        db.session.add(bug_report)
        db.session.commit()

        flash('Bug report created successfully!', 'success')
        return redirect(url_for('main.view_bug_report', report_id=bug_report.id))

    # Pre-generate report for preview
    generator = BugReportGenerator()
    device_info = json.loads(log_file.device_info) if log_file.device_info else {}
    preview = generator.generate_report(issue.to_dict(), device_info=device_info)

    return render_template('create_bug_report.html',
                           issue=issue,
                           log_file=log_file,
                           preview=preview)


@main_bp.route('/bug-report/jira', methods=['GET'])
@main_bp.route('/bug-report/jira/<int:issue_id>', methods=['GET'])
def create_jira_bug(issue_id=None):
    """Create a Jira bug - with automatic (from issue) or manual mode"""
    from flask import request

    issue = None
    log_file = None
    context_entries = []

    # Check for URL parameters (from AI analysis quick bug creation)
    prefill_title = request.args.get('title', '')
    prefill_severity = request.args.get('severity', '')
    prefill_description = request.args.get('description', '')

    if issue_id:
        issue = Issue.query.get_or_404(issue_id)
        log_file = issue.log_file

        # Get context entries for the issue
        affected_lines = json.loads(issue.affected_lines) if issue.affected_lines else []
        if affected_lines:
            first_line = min(affected_lines)
            last_line = max(affected_lines)
            context_entries = LogEntry.query.filter(
                LogEntry.log_file_id == log_file.id,
                LogEntry.line_number >= first_line - 10,
                LogEntry.line_number <= last_line + 10
            ).order_by(LogEntry.line_number).all()

    return render_template('create_bug_jira.html',
                           issue=issue,
                           log_file=log_file,
                           context_entries=context_entries,
                           prefill_title=prefill_title,
                           prefill_severity=prefill_severity,
                           prefill_description=prefill_description)


@main_bp.route('/bug-report/<int:report_id>')
def view_bug_report(report_id):
    """View a bug report"""
    report = BugReport.query.get_or_404(report_id)
    return render_template('bug_report.html', report=report)


@main_bp.route('/bug-reports')
def bug_reports_list():
    """List all bug reports"""
    reports = BugReport.query.order_by(BugReport.created_at.desc()).all()
    return render_template('bug_reports.html', reports=reports)


@main_bp.route('/bug-report/<int:report_id>/export/<format>')
def export_bug_report(report_id, format):
    """Export bug report in specified format"""
    report = BugReport.query.get_or_404(report_id)
    generator = BugReportGenerator()

    if format == 'json':
        content = generator.export_to_json(report.to_dict())
        mimetype = 'application/json'
        filename = f'bug_report_{report_id}.json'
    elif format == 'markdown':
        content = generator.export_to_markdown(report.to_dict())
        mimetype = 'text/markdown'
        filename = f'bug_report_{report_id}.md'
    else:
        content = generator.export_to_text(report.to_dict())
        mimetype = 'text/plain'
        filename = f'bug_report_{report_id}.txt'

    from flask import Response
    response = Response(content, mimetype=mimetype)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


@main_bp.route('/charts/<int:file_id>')
def charts(file_id):
    """Charts and visualization page"""
    log_file = LogFile.query.get_or_404(file_id)
    return render_template('charts.html', log_file=log_file)


@main_bp.route('/delete/<int:file_id>', methods=['POST'])
def delete_log(file_id):
    """Delete a log file and its data"""
    log_file = LogFile.query.get_or_404(file_id)

    # Delete file from disk
    file_path = current_app.config['UPLOAD_FOLDER'] / log_file.filename
    if file_path.exists():
        file_path.unlink()

    # Delete from database (cascades to entries and issues)
    db.session.delete(log_file)
    db.session.commit()

    flash(f'Log file "{log_file.original_filename}" deleted successfully.', 'success')
    return redirect(url_for('main.index'))


@main_bp.route('/delete-all', methods=['POST'])
def delete_all():
    """Delete all log files, entries, issues, and bug reports"""
    # Delete all files from uploads folder
    upload_folder = current_app.config['UPLOAD_FOLDER']
    for file_path in upload_folder.iterdir():
        if file_path.is_file():
            file_path.unlink()

    # Delete all database records
    BugReport.query.delete()
    Issue.query.delete()
    LogEntry.query.delete()
    LogFile.query.delete()
    db.session.commit()

    flash('All history deleted successfully.', 'success')
    return redirect(url_for('main.index'))
