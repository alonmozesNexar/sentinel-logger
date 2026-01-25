"""
Event Detector Service
Detects key events and phases in camera log files
"""
import re
from collections import defaultdict


class EventDetector:
    """Detects key events and phases in log files"""

    # Event categories with their detection patterns
    EVENT_PATTERNS = {
        'ota_update': {
            'name': 'OTA / Firmware Update',
            'icon': 'bi-cloud-download',
            'color': 'primary',
            'patterns': [
                r'ota', r'upgrade', r'firmware', r'fwupdate', r'software.?update',
                r'downloading.?firmware', r'flash', r'update.?version', r'new.?version',
                r'upgrading', r'update.?complete', r'update.?failed', r'rollback'
            ],
            'description': 'Firmware/software update events'
        },
        'boot_sequence': {
            'name': 'Boot / Startup',
            'icon': 'bi-power',
            'color': 'success',
            'patterns': [
                r'boot', r'startup', r'starting', r'init', r'kernel',
                r'bootloader', r'power.?on', r'system.?start', r'loading',
                r'mounted', r'systemd', r'service.?start'
            ],
            'description': 'System boot and startup events'
        },
        'shutdown': {
            'name': 'Shutdown / Power Off',
            'icon': 'bi-power',
            'color': 'danger',
            'patterns': [
                r'shutdown', r'power.?off', r'shutting.?down', r'halt',
                r'poweroff', r'reboot', r'restart', r'stopping', r'terminated',
                r'system.?stop', r'going.?down'
            ],
            'description': 'System shutdown and power events'
        },
        'recording': {
            'name': 'Recording / Video',
            'icon': 'bi-record-circle',
            'color': 'danger',
            'patterns': [
                r'recording', r'record', r'video.?start', r'video.?stop',
                r'capture', r'clip', r'segment', r'encoder', r'h264', r'h265',
                r'stream', r'frame', r'fps', r'bitrate'
            ],
            'description': 'Video recording and capture events'
        },
        'storage': {
            'name': 'Storage / SD Card',
            'icon': 'bi-sd-card',
            'color': 'warning',
            'patterns': [
                r'sd.?card', r'sdcard', r'storage', r'mount', r'unmount',
                r'filesystem', r'disk', r'mmc', r'emmc', r'partition',
                r'format', r'space', r'full', r'write.?error', r'read.?error'
            ],
            'description': 'Storage and SD card events'
        },
        'network': {
            'name': 'Network / WiFi',
            'icon': 'bi-wifi',
            'color': 'info',
            'patterns': [
                r'wifi', r'wlan', r'network', r'connect', r'disconnect',
                r'ssid', r'ip.?address', r'dhcp', r'ethernet', r'socket',
                r'http', r'upload', r'download', r'cloud', r'server'
            ],
            'description': 'Network and connectivity events'
        },
        'collision': {
            'name': 'Collision / Impact',
            'icon': 'bi-exclamation-triangle',
            'color': 'danger',
            'patterns': [
                r'collision', r'impact', r'g.?sensor', r'gsensor', r'accelerometer',
                r'accident', r'crash.?detect', r'event.?trigger', r'emergency'
            ],
            'description': 'Collision and impact detection events'
        },
        'gps': {
            'name': 'GPS / Location',
            'icon': 'bi-geo-alt',
            'color': 'success',
            'patterns': [
                r'gps', r'gnss', r'location', r'satellite', r'fix',
                r'coordinates', r'latitude', r'longitude', r'nmea', r'position'
            ],
            'description': 'GPS and location events'
        },
        'camera': {
            'name': 'Camera / Sensor',
            'icon': 'bi-camera-video',
            'color': 'primary',
            'patterns': [
                r'camera', r'sensor', r'isp', r'lens', r'exposure',
                r'road.?facing', r'interior', r'front.?cam', r'rear.?cam',
                r'image', r'resolution', r'focus'
            ],
            'description': 'Camera and sensor events'
        },
        'error': {
            'name': 'Errors / Failures',
            'icon': 'bi-x-circle',
            'color': 'danger',
            'patterns': [
                r'error', r'fail', r'failed', r'failure', r'exception',
                r'crash', r'panic', r'fatal', r'critical', r'abort'
            ],
            'description': 'Error and failure events'
        },
        'temperature': {
            'name': 'Temperature / Thermal',
            'icon': 'bi-thermometer-half',
            'color': 'warning',
            'patterns': [
                r'temperature', r'temp', r'thermal', r'overheat', r'cooling',
                r'throttle', r'hot', r'cold', r'celsius', r'fahrenheit'
            ],
            'description': 'Temperature and thermal events'
        },
        'power': {
            'name': 'Power / Battery',
            'icon': 'bi-battery-half',
            'color': 'warning',
            'patterns': [
                r'battery', r'power', r'voltage', r'charging', r'low.?power',
                r'pmic', r'usb.?power', r'acc', r'ignition'
            ],
            'description': 'Power and battery events'
        },
        'audio': {
            'name': 'Audio / Microphone',
            'icon': 'bi-mic',
            'color': 'secondary',
            'patterns': [
                r'audio', r'microphone', r'mic', r'speaker', r'sound',
                r'voice', r'mute', r'volume'
            ],
            'description': 'Audio and microphone events'
        },
        'config': {
            'name': 'Configuration',
            'icon': 'bi-gear',
            'color': 'secondary',
            'patterns': [
                r'config', r'setting', r'parameter', r'option', r'preference',
                r'policy', r'mode', r'enable', r'disable'
            ],
            'description': 'Configuration and settings events'
        },
        'service': {
            'name': 'Services / Processes',
            'icon': 'bi-diagram-3',
            'color': 'info',
            'patterns': [
                r'service', r'daemon', r'process', r'thread', r'worker',
                r'started', r'stopped', r'restart', r'spawn', r'kill'
            ],
            'description': 'Service and process lifecycle events'
        }
    }

    def detect_events(self, entries):
        """
        Detect key events in log entries

        Args:
            entries: List of log entry dicts with 'raw_content', 'line_number', 'timestamp', etc.

        Returns:
            Dict with detected events by category
        """
        events = {}

        for category, config in self.EVENT_PATTERNS.items():
            category_entries = []
            pattern = '|'.join(config['patterns'])
            regex = re.compile(pattern, re.IGNORECASE)

            for entry in entries:
                content = entry.get('raw_content', '') or entry.get('message', '') or ''
                if regex.search(content):
                    category_entries.append({
                        'line_number': entry.get('line_number'),
                        'timestamp': entry.get('timestamp'),
                        'severity': entry.get('severity'),
                        'service': entry.get('service'),
                        'component': entry.get('component'),
                        'message': entry.get('message', '')[:200] or content[:200],
                        'raw_content': content[:300]
                    })

            if category_entries:
                # Get first and last occurrence
                first_entry = min(category_entries, key=lambda x: x['line_number'])
                last_entry = max(category_entries, key=lambda x: x['line_number'])

                # Count by severity
                severity_counts = defaultdict(int)
                for e in category_entries:
                    sev = e.get('severity', 'INFO')
                    severity_counts[sev] += 1

                events[category] = {
                    'name': config['name'],
                    'icon': config['icon'],
                    'color': config['color'],
                    'description': config['description'],
                    'count': len(category_entries),
                    'first_line': first_entry['line_number'],
                    'last_line': last_entry['line_number'],
                    'first_timestamp': first_entry.get('timestamp'),
                    'last_timestamp': last_entry.get('timestamp'),
                    'severity_counts': dict(severity_counts),
                    'has_errors': severity_counts.get('ERROR', 0) + severity_counts.get('CRITICAL', 0) > 0,
                    'sample_entries': category_entries[:5]  # First 5 entries as samples
                }

        return events

    def get_timeline(self, entries):
        """
        Create a timeline of major events

        Returns a list of significant events in chronological order
        """
        events = self.detect_events(entries)

        timeline = []
        for category, data in events.items():
            if data['count'] > 0:
                timeline.append({
                    'category': category,
                    'name': data['name'],
                    'icon': data['icon'],
                    'color': data['color'],
                    'line_number': data['first_line'],
                    'timestamp': data['first_timestamp'],
                    'count': data['count'],
                    'has_errors': data['has_errors']
                })

        # Sort by line number (chronological order in log)
        timeline.sort(key=lambda x: x['line_number'])

        return timeline

    def get_summary(self, entries):
        """
        Get a summary of the log file

        Returns dict with key statistics and detected events
        """
        events = self.detect_events(entries)

        # Calculate totals
        total_events = sum(e['count'] for e in events.values())
        categories_with_errors = [k for k, v in events.items() if v.get('has_errors')]

        return {
            'total_events': total_events,
            'categories_detected': len(events),
            'categories_with_errors': len(categories_with_errors),
            'events': events,
            'timeline': self.get_timeline(entries)
        }
