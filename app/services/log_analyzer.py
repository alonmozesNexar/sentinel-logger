"""
Log Analyzer Service
Automatically discovers and analyzes what's in the log file
"""
from collections import defaultdict


class LogAnalyzer:
    """Analyzes log files and discovers what operations/events are present"""

    def analyze(self, entries):
        """
        Analyze log entries and discover what's in the log

        Returns a summary of everything found in the log
        """
        if not entries:
            return {'discoveries': [], 'services': [], 'components': [], 'summary': {}}

        # Collect all unique values
        services = defaultdict(lambda: {'count': 0, 'errors': 0, 'warnings': 0, 'entries': []})
        components = defaultdict(lambda: {'count': 0, 'errors': 0, 'warnings': 0, 'entries': []})
        keywords_found = defaultdict(lambda: {'count': 0, 'lines': [], 'services': set()})

        # Keywords to look for (operations/events)
        operation_keywords = {
            # Updates
            'ota': 'OTA Update',
            'upgrade': 'Upgrade',
            'firmware': 'Firmware',
            'update': 'Update',
            'version': 'Version Info',

            # Boot/Shutdown
            'boot': 'Boot',
            'startup': 'Startup',
            'shutdown': 'Shutdown',
            'reboot': 'Reboot',
            'init': 'Initialization',

            # Recording
            'recording': 'Recording',
            'video': 'Video',
            'capture': 'Capture',
            'stream': 'Stream',
            'encoder': 'Encoder',

            # Storage
            'storage': 'Storage',
            'sdcard': 'SD Card',
            'sd card': 'SD Card',
            'mount': 'Mount',
            'disk': 'Disk',

            # Network
            'wifi': 'WiFi',
            'network': 'Network',
            'connect': 'Connection',
            'upload': 'Upload',
            'download': 'Download',
            'cloud': 'Cloud',

            # Events
            'collision': 'Collision',
            'impact': 'Impact',
            'event': 'Event',
            'trigger': 'Trigger',
            'alert': 'Alert',

            # GPS
            'gps': 'GPS',
            'location': 'Location',
            'gnss': 'GNSS',

            # Camera
            'camera': 'Camera',
            'sensor': 'Sensor',
            'lens': 'Lens',

            # Errors
            'error': 'Error',
            'fail': 'Failure',
            'crash': 'Crash',
            'timeout': 'Timeout',
            'exception': 'Exception',

            # Power
            'power': 'Power',
            'battery': 'Battery',
            'voltage': 'Voltage',

            # Config
            'config': 'Configuration',
            'setting': 'Settings',
            'policy': 'Policy',
        }

        # Analyze each entry
        for entry in entries:
            service = entry.get('service') or 'unknown'
            component = entry.get('component') or ''
            severity = entry.get('severity', 'INFO')
            content = (entry.get('raw_content', '') or entry.get('message', '') or '').lower()
            line_num = entry.get('line_number', 0)

            # Track services
            services[service]['count'] += 1
            if severity in ['ERROR', 'CRITICAL']:
                services[service]['errors'] += 1
            elif severity == 'WARNING':
                services[service]['warnings'] += 1
            if len(services[service]['entries']) < 5:
                services[service]['entries'].append(entry)

            # Track components
            if component:
                components[component]['count'] += 1
                if severity in ['ERROR', 'CRITICAL']:
                    components[component]['errors'] += 1
                elif severity == 'WARNING':
                    components[component]['warnings'] += 1
                if len(components[component]['entries']) < 5:
                    components[component]['entries'].append(entry)

            # Find keywords
            for keyword, label in operation_keywords.items():
                if keyword in content:
                    keywords_found[label]['count'] += 1
                    if len(keywords_found[label]['lines']) < 100:
                        keywords_found[label]['lines'].append(line_num)
                    keywords_found[label]['services'].add(service)

        # Build discoveries list (sorted by count)
        discoveries = []
        for label, data in sorted(keywords_found.items(), key=lambda x: -x[1]['count']):
            if data['count'] > 0:
                discoveries.append({
                    'name': label,
                    'count': data['count'],
                    'lines': data['lines'][:20],  # First 20 lines
                    'services': list(data['services'])[:10],
                    'first_line': min(data['lines']) if data['lines'] else 0,
                    'last_line': max(data['lines']) if data['lines'] else 0
                })

        # Build services list
        services_list = []
        for name, data in sorted(services.items(), key=lambda x: -x[1]['count']):
            if name and name != 'unknown':
                services_list.append({
                    'name': name,
                    'count': data['count'],
                    'errors': data['errors'],
                    'warnings': data['warnings'],
                    'has_errors': data['errors'] > 0,
                    'sample_entries': data['entries'][:3]
                })

        # Build components list
        components_list = []
        for name, data in sorted(components.items(), key=lambda x: -x[1]['count']):
            if name:
                components_list.append({
                    'name': name,
                    'count': data['count'],
                    'errors': data['errors'],
                    'warnings': data['warnings'],
                    'has_errors': data['errors'] > 0
                })

        # Summary stats
        total_entries = len(entries)
        total_errors = sum(1 for e in entries if e.get('severity') in ['ERROR', 'CRITICAL'])
        total_warnings = sum(1 for e in entries if e.get('severity') == 'WARNING')

        return {
            'discoveries': discoveries,
            'services': services_list,
            'components': components_list,
            'summary': {
                'total_entries': total_entries,
                'total_errors': total_errors,
                'total_warnings': total_warnings,
                'unique_services': len(services_list),
                'unique_components': len(components_list),
                'topics_found': len(discoveries)
            }
        }

    def get_entries_for_topic(self, entries, topic_name):
        """Get all entries related to a specific topic/keyword"""
        keyword = topic_name.lower()
        matching = []

        for entry in entries:
            content = (entry.get('raw_content', '') or entry.get('message', '') or '').lower()
            if keyword in content:
                matching.append(entry)

        return matching

    def get_entries_for_service(self, entries, service_name):
        """Get all entries for a specific service"""
        return [e for e in entries if e.get('service') == service_name]
