"""
Smart Log Analyzer
AI-like analysis of log files - finds root causes, correlates events, provides detailed explanations
"""
import re


class SmartAnalyzer:
    """Intelligent log analyzer that provides deep insights into issues"""

    # Known issue patterns with detailed analysis info
    ISSUE_KNOWLEDGE = {
        # Storage Issues
        'sd_card_error': {
            'patterns': [r'sd.*error', r'mmc.*fail', r'storage.*error', r'write.*fail.*sd', r'read.*fail.*sd'],
            'name': 'SD Card Error',
            'category': 'Storage',
            'severity': 'HIGH',
            'description': 'SD card read/write operation failed',
            'probable_causes': [
                'SD card is corrupted or damaged',
                'SD card is not properly inserted',
                'SD card is full (no space left)',
                'SD card file system error',
                'Hardware connection issue'
            ],
            'investigation_steps': [
                'Check SD card insertion and contacts',
                'Check available storage space',
                'Look for file system errors in previous logs',
                'Check if SD card works in another device',
                'Look for power issues that may have corrupted the card'
            ],
            'related_services': ['storage', 'video', 'recording', 'mmc']
        },
        'storage_full': {
            'patterns': [r'no.*space.*left', r'storage.*full', r'disk.*full', r'cannot.*write.*space'],
            'name': 'Storage Full',
            'category': 'Storage',
            'severity': 'HIGH',
            'description': 'Storage device has no free space',
            'probable_causes': [
                'Too many recordings stored',
                'Old files not being deleted',
                'Loop recording not configured properly',
                'Large event clips consuming space'
            ],
            'investigation_steps': [
                'Check storage usage and available space',
                'Verify loop recording settings',
                'Check if old files are being cleaned up',
                'Look for unusually large files'
            ],
            'related_services': ['storage', 'recording', 'cleanup']
        },

        # Camera Issues
        'camera_init_fail': {
            'patterns': [r'camera.*init.*fail', r'sensor.*fail', r'isp.*error', r'camera.*not.*found'],
            'name': 'Camera Initialization Failed',
            'category': 'Camera',
            'severity': 'CRITICAL',
            'description': 'Camera sensor failed to initialize',
            'probable_causes': [
                'Camera sensor hardware failure',
                'Driver or firmware issue',
                'Power supply problem to camera module',
                'Loose cable connection',
                'Temperature out of operating range'
            ],
            'investigation_steps': [
                'Check camera hardware connections',
                'Look for temperature warnings before failure',
                'Check power supply status',
                'Look for driver loading errors',
                'Check if issue persists after reboot'
            ],
            'related_services': ['camera', 'sensor', 'isp', 'video']
        },
        'video_encoder_error': {
            'patterns': [r'encoder.*error', r'encode.*fail', r'h264.*error', r'h265.*error', r'codec.*fail'],
            'name': 'Video Encoder Error',
            'category': 'Video',
            'severity': 'HIGH',
            'description': 'Video encoding process failed',
            'probable_causes': [
                'Encoder hardware overload',
                'Memory allocation failure',
                'Invalid video parameters',
                'Driver issue',
                'Too many concurrent streams'
            ],
            'investigation_steps': [
                'Check memory usage at time of error',
                'Look for resolution/bitrate configuration issues',
                'Check number of active streams',
                'Look for thermal throttling'
            ],
            'related_services': ['encoder', 'video', 'stream', 'recording']
        },

        # Network Issues
        'wifi_disconnect': {
            'patterns': [r'wifi.*disconnect', r'wlan.*lost', r'network.*down', r'connection.*lost'],
            'name': 'WiFi Disconnection',
            'category': 'Network',
            'severity': 'MEDIUM',
            'description': 'WiFi connection was lost',
            'probable_causes': [
                'Weak signal strength',
                'Access point issue',
                'Network congestion',
                'Authentication failure',
                'Power saving mode disconnect'
            ],
            'investigation_steps': [
                'Check signal strength before disconnect',
                'Look for authentication errors',
                'Check if device moved out of range',
                'Verify access point status'
            ],
            'related_services': ['wifi', 'wlan', 'network', 'connection']
        },
        'upload_fail': {
            'patterns': [r'upload.*fail', r'cloud.*error', r'sync.*fail', r'transfer.*fail', r'http.*error'],
            'name': 'Cloud Upload Failed',
            'category': 'Network',
            'severity': 'MEDIUM',
            'description': 'Failed to upload data to cloud server',
            'probable_causes': [
                'Network connectivity issue',
                'Server unavailable',
                'Authentication expired',
                'File too large',
                'Timeout during transfer'
            ],
            'investigation_steps': [
                'Check network connectivity at time of failure',
                'Look for server response codes',
                'Check authentication status',
                'Verify file size and upload limits'
            ],
            'related_services': ['upload', 'cloud', 'sync', 'http', 'network']
        },

        # OTA Issues
        'ota_fail': {
            'patterns': [r'ota.*fail', r'upgrade.*fail', r'firmware.*fail', r'update.*error'],
            'name': 'OTA Update Failed',
            'category': 'System',
            'severity': 'HIGH',
            'description': 'Firmware update process failed',
            'probable_causes': [
                'Download interrupted',
                'Verification/checksum failed',
                'Insufficient storage space',
                'Power loss during update',
                'Incompatible firmware version'
            ],
            'investigation_steps': [
                'Check download completion status',
                'Look for checksum/signature errors',
                'Verify available storage space',
                'Check power status during update',
                'Look for version compatibility info'
            ],
            'related_services': ['ota', 'upgrade', 'firmware', 'update']
        },

        # Memory Issues
        'out_of_memory': {
            'patterns': [r'out.*of.*memory', r'oom', r'cannot.*allocate', r'memory.*exhausted', r'malloc.*fail'],
            'name': 'Out of Memory',
            'category': 'System',
            'severity': 'CRITICAL',
            'description': 'System ran out of available memory',
            'probable_causes': [
                'Memory leak in application',
                'Too many concurrent processes',
                'Large buffer allocation failure',
                'Fragmented memory',
                'Insufficient system RAM'
            ],
            'investigation_steps': [
                'Check memory usage trend before OOM',
                'Identify which process was killed',
                'Look for memory leak patterns',
                'Check for large allocation requests'
            ],
            'related_services': ['system', 'kernel', 'memory']
        },

        # Process Issues
        'service_crash': {
            'patterns': [r'segfault', r'segmentation.*fault', r'core.*dump', r'signal.*11', r'crashed'],
            'name': 'Service Crash',
            'category': 'System',
            'severity': 'CRITICAL',
            'description': 'A service crashed unexpectedly',
            'probable_causes': [
                'Software bug (null pointer, buffer overflow)',
                'Memory corruption',
                'Stack overflow',
                'Incompatible library version',
                'Hardware failure'
            ],
            'investigation_steps': [
                'Identify which service crashed',
                'Look for error messages before crash',
                'Check if crash is reproducible',
                'Look for memory issues',
                'Check core dump if available'
            ],
            'related_services': ['system', 'kernel']
        },
        'service_timeout': {
            'patterns': [r'timeout', r'timed.*out', r'no.*response', r'watchdog', r'hung'],
            'name': 'Service Timeout',
            'category': 'System',
            'severity': 'HIGH',
            'description': 'Service did not respond within expected time',
            'probable_causes': [
                'Service is overloaded',
                'Deadlock condition',
                'Waiting for unavailable resource',
                'High CPU usage',
                'I/O blocking'
            ],
            'investigation_steps': [
                'Check CPU usage at time of timeout',
                'Look for resource contention',
                'Identify what the service was waiting for',
                'Check for deadlock patterns'
            ],
            'related_services': ['system', 'watchdog']
        },

        # Power Issues
        'power_loss': {
            'patterns': [r'power.*loss', r'unexpected.*shutdown', r'power.*fail', r'battery.*critical'],
            'name': 'Power Loss',
            'category': 'Power',
            'severity': 'HIGH',
            'description': 'Device lost power unexpectedly',
            'probable_causes': [
                'Vehicle power disconnected',
                'Battery depleted',
                'Power management failure',
                'Loose power connection'
            ],
            'investigation_steps': [
                'Check power events before shutdown',
                'Look for low voltage warnings',
                'Check ignition/ACC status',
                'Verify power connection integrity'
            ],
            'related_services': ['power', 'battery', 'pmic', 'system']
        },

        # GPS Issues
        'gps_no_fix': {
            'patterns': [r'gps.*no.*fix', r'gnss.*fail', r'no.*satellite', r'position.*invalid'],
            'name': 'GPS No Fix',
            'category': 'GPS',
            'severity': 'LOW',
            'description': 'Unable to acquire GPS position',
            'probable_causes': [
                'Obstructed sky view (garage, tunnel)',
                'GPS antenna issue',
                'Cold start taking longer',
                'GPS module failure'
            ],
            'investigation_steps': [
                'Check location/environment',
                'Look for antenna connection issues',
                'Check time since last valid fix',
                'Verify GPS module status'
            ],
            'related_services': ['gps', 'gnss', 'location']
        },

        # Collision/Event Issues
        'collision_detected': {
            'patterns': [r'collision.*detect', r'impact.*detect', r'g.?sensor.*trigger', r'accident'],
            'name': 'Collision Detected',
            'category': 'Event',
            'severity': 'HIGH',
            'description': 'Impact/collision event was detected',
            'probable_causes': [
                'Vehicle collision occurred',
                'Hard braking event',
                'Pothole or road bump',
                'G-sensor sensitivity too high',
                'False trigger from vibration'
            ],
            'investigation_steps': [
                'Check G-sensor values at trigger time',
                'Look for pre-event video',
                'Check GPS location at event time',
                'Verify event clip was saved'
            ],
            'related_services': ['collision', 'gsensor', 'event', 'recording']
        },

        # Temperature Issues
        'overheating': {
            'patterns': [r'overheat', r'temperature.*high', r'thermal.*shutdown', r'temp.*critical'],
            'name': 'Overheating',
            'category': 'Hardware',
            'severity': 'HIGH',
            'description': 'Device temperature exceeded safe limits',
            'probable_causes': [
                'High ambient temperature',
                'Direct sunlight exposure',
                'Poor ventilation',
                'High processing load',
                'Cooling system failure'
            ],
            'investigation_steps': [
                'Check temperature readings before shutdown',
                'Look for high CPU/GPU usage',
                'Check environmental conditions',
                'Verify cooling system operation'
            ],
            'related_services': ['thermal', 'temperature', 'system']
        }
    }

    def analyze(self, entries):
        """
        Perform deep analysis of log entries

        Returns detailed issue analysis with root causes and explanations
        """
        if not entries:
            return {'issues': [], 'summary': {}}

        analyzed_issues = []

        # Find all issues
        for issue_id, issue_info in self.ISSUE_KNOWLEDGE.items():
            matches = self._find_issue_matches(entries, issue_info)

            if matches:
                # Get context around the issue
                context = self._get_issue_context(entries, matches)

                # Analyze related events
                related_events = self._find_related_events(entries, matches, issue_info)

                # Get participating services
                services = self._get_services_involved(matches + related_events)

                # Build timeline
                timeline = self._build_issue_timeline(matches, related_events)

                analyzed_issues.append({
                    'id': issue_id,
                    'name': issue_info['name'],
                    'category': issue_info['category'],
                    'severity': issue_info['severity'],
                    'description': issue_info['description'],
                    'occurrence_count': len(matches),
                    'first_occurrence': matches[0]['line_number'],
                    'last_occurrence': matches[-1]['line_number'],
                    'probable_causes': issue_info['probable_causes'],
                    'investigation_steps': issue_info['investigation_steps'],
                    'services_involved': services,
                    'timeline': timeline,
                    'sample_entries': matches[:5],
                    'context_before': context['before'],
                    'context_after': context['after']
                })

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        analyzed_issues.sort(key=lambda x: severity_order.get(x['severity'], 4))

        return {
            'issues': analyzed_issues,
            'summary': {
                'total_issues': len(analyzed_issues),
                'critical': sum(1 for i in analyzed_issues if i['severity'] == 'CRITICAL'),
                'high': sum(1 for i in analyzed_issues if i['severity'] == 'HIGH'),
                'medium': sum(1 for i in analyzed_issues if i['severity'] == 'MEDIUM'),
                'low': sum(1 for i in analyzed_issues if i['severity'] == 'LOW')
            }
        }

    def _find_issue_matches(self, entries, issue_info):
        """Find entries matching issue patterns"""
        matches = []
        combined_pattern = '|'.join(issue_info['patterns'])
        regex = re.compile(combined_pattern, re.IGNORECASE)

        for entry in entries:
            content = entry.get('raw_content', '') or entry.get('message', '') or ''
            if regex.search(content):
                matches.append(entry)

        return matches

    def _get_issue_context(self, entries, matches):
        """Get log entries before and after the issue"""
        if not matches:
            return {'before': [], 'after': []}

        first_match_line = matches[0]['line_number']
        last_match_line = matches[-1]['line_number']

        before = []
        after = []

        for entry in entries:
            line = entry['line_number']
            if first_match_line - 10 <= line < first_match_line:
                before.append(entry)
            elif last_match_line < line <= last_match_line + 5:
                after.append(entry)

        return {'before': before[-10:], 'after': after[:5]}

    def _find_related_events(self, entries, matches, issue_info):
        """Find events related to the issue"""
        if not matches:
            return []

        related = []
        first_line = matches[0]['line_number']
        last_line = matches[-1]['line_number']

        # Look for related service entries
        related_services = issue_info.get('related_services', [])

        for entry in entries:
            line = entry['line_number']
            # Only look in the vicinity of the issue
            if first_line - 50 <= line <= last_line + 20:
                service = (entry.get('service', '') or '').lower()
                content = (entry.get('raw_content', '') or '').lower()

                for rel_svc in related_services:
                    if rel_svc in service or rel_svc in content:
                        if entry not in matches:
                            related.append(entry)
                        break

        return related[:20]  # Limit to 20 related events

    def _get_services_involved(self, entries):
        """Get unique services from entries"""
        services = set()
        for entry in entries:
            if entry.get('service'):
                services.add(entry['service'])
        return sorted(list(services))

    def _build_issue_timeline(self, matches, related_events):
        """Build a timeline of events leading to and following the issue"""
        all_events = matches + related_events
        all_events.sort(key=lambda x: x['line_number'])

        timeline = []
        for entry in all_events[:15]:  # Limit to 15 events
            is_error = entry.get('severity') in ['ERROR', 'CRITICAL']
            timeline.append({
                'line': entry['line_number'],
                'service': entry.get('service', '-'),
                'message': (entry.get('message', '') or entry.get('raw_content', ''))[:100],
                'severity': entry.get('severity', 'INFO'),
                'is_issue': entry in matches
            })

        return timeline
