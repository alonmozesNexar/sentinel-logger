"""
Flow Detector Service
Detects complete operational flows/phases in camera log files
"""
import re
from collections import defaultdict


class FlowDetector:
    """Detects operational flows and phases in log files"""

    # Flow definitions with start/end patterns and related keywords
    FLOWS = {
        'ota_update': {
            'name': 'OTA / Firmware Update',
            'icon': 'bi-cloud-download',
            'color': 'primary',
            'start_patterns': [
                r'ota.*start', r'upgrade.*start', r'firmware.*download',
                r'checking.*update', r'update.*available', r'new.*version.*found',
                r'starting.*upgrade', r'fwupdate'
            ],
            'end_patterns': [
                r'ota.*complete', r'upgrade.*complete', r'update.*success',
                r'firmware.*installed', r'update.*finished', r'reboot.*after.*update'
            ],
            'related_patterns': [
                r'ota', r'upgrade', r'firmware', r'update', r'version',
                r'download', r'flash', r'install', r'verify', r'rollback',
                r'partition', r'image', r'checksum', r'signature'
            ],
            'description': 'Firmware/software update process'
        },
        'boot_sequence': {
            'name': 'Boot / Startup Sequence',
            'icon': 'bi-power',
            'color': 'success',
            'start_patterns': [
                r'kernel.*boot', r'system.*start', r'boot.*start',
                r'power.*on', r'bootloader', r'init.*start'
            ],
            'end_patterns': [
                r'boot.*complete', r'system.*ready', r'startup.*complete',
                r'all.*services.*started', r'ready.*for.*operation'
            ],
            'related_patterns': [
                r'boot', r'kernel', r'init', r'systemd', r'mount',
                r'loading', r'driver', r'module', r'service.*start',
                r'daemon.*start', r'initialization'
            ],
            'description': 'System boot and initialization'
        },
        'shutdown_sequence': {
            'name': 'Shutdown / Power Down',
            'icon': 'bi-power',
            'color': 'danger',
            'start_patterns': [
                r'shutdown.*start', r'shutting.*down', r'power.*off.*request',
                r'system.*halt', r'going.*down'
            ],
            'end_patterns': [
                r'shutdown.*complete', r'power.*off', r'halt.*complete',
                r'system.*halted'
            ],
            'related_patterns': [
                r'shutdown', r'stop', r'halt', r'terminate', r'kill',
                r'unmount', r'sync', r'closing', r'cleanup'
            ],
            'description': 'System shutdown process'
        },
        'recording_session': {
            'name': 'Recording Session',
            'icon': 'bi-record-circle',
            'color': 'danger',
            'start_patterns': [
                r'recording.*start', r'start.*record', r'video.*start',
                r'capture.*start', r'begin.*recording'
            ],
            'end_patterns': [
                r'recording.*stop', r'stop.*record', r'video.*stop',
                r'capture.*stop', r'recording.*complete', r'segment.*saved'
            ],
            'related_patterns': [
                r'record', r'video', r'capture', r'stream', r'encoder',
                r'segment', r'clip', r'frame', r'codec', r'bitrate',
                r'resolution', r'fps', r'h264', r'h265'
            ],
            'description': 'Video recording session'
        },
        'collision_event': {
            'name': 'Collision / Impact Event',
            'icon': 'bi-exclamation-triangle',
            'color': 'warning',
            'start_patterns': [
                r'collision.*detect', r'impact.*detect', r'g.?sensor.*trigger',
                r'accelerometer.*event', r'crash.*detect'
            ],
            'end_patterns': [
                r'collision.*handled', r'event.*saved', r'clip.*saved',
                r'emergency.*upload', r'event.*complete'
            ],
            'related_patterns': [
                r'collision', r'impact', r'gsensor', r'g-sensor', r'accelerometer',
                r'event', r'trigger', r'emergency', r'alert', r'clip'
            ],
            'description': 'Collision detection and handling'
        },
        'wifi_connection': {
            'name': 'WiFi Connection',
            'icon': 'bi-wifi',
            'color': 'info',
            'start_patterns': [
                r'wifi.*connect', r'wlan.*associat', r'network.*connect',
                r'joining.*network', r'ssid'
            ],
            'end_patterns': [
                r'wifi.*connected', r'ip.*obtained', r'dhcp.*complete',
                r'network.*ready', r'connection.*established'
            ],
            'related_patterns': [
                r'wifi', r'wlan', r'ssid', r'dhcp', r'ip.*address',
                r'signal', r'auth', r'wpa', r'connect', r'disconnect'
            ],
            'description': 'WiFi connection process'
        },
        'cloud_upload': {
            'name': 'Cloud Upload',
            'icon': 'bi-cloud-upload',
            'color': 'info',
            'start_patterns': [
                r'upload.*start', r'cloud.*upload', r'sending.*to.*server',
                r'sync.*start'
            ],
            'end_patterns': [
                r'upload.*complete', r'upload.*success', r'sync.*complete',
                r'transfer.*complete'
            ],
            'related_patterns': [
                r'upload', r'cloud', r'server', r'sync', r'transfer',
                r'http', r'api', r'send', r'post'
            ],
            'description': 'Cloud upload/sync process'
        },
        'storage_operation': {
            'name': 'Storage Operation',
            'icon': 'bi-sd-card',
            'color': 'secondary',
            'start_patterns': [
                r'sd.*mount', r'storage.*init', r'disk.*check',
                r'format.*start', r'partition'
            ],
            'end_patterns': [
                r'mount.*success', r'storage.*ready', r'format.*complete',
                r'sd.*ready'
            ],
            'related_patterns': [
                r'sd', r'storage', r'mount', r'unmount', r'disk',
                r'partition', r'filesystem', r'format', r'space', r'write'
            ],
            'description': 'Storage/SD card operations'
        },
        'gps_acquisition': {
            'name': 'GPS Acquisition',
            'icon': 'bi-geo-alt',
            'color': 'success',
            'start_patterns': [
                r'gps.*start', r'gnss.*init', r'searching.*satellite',
                r'gps.*cold.*start', r'gps.*warm.*start'
            ],
            'end_patterns': [
                r'gps.*fix', r'position.*acquired', r'location.*valid',
                r'satellite.*lock'
            ],
            'related_patterns': [
                r'gps', r'gnss', r'satellite', r'fix', r'nmea',
                r'latitude', r'longitude', r'position', r'coordinates'
            ],
            'description': 'GPS satellite acquisition'
        },
        'camera_init': {
            'name': 'Camera Initialization',
            'icon': 'bi-camera-video',
            'color': 'primary',
            'start_patterns': [
                r'camera.*init', r'sensor.*init', r'isp.*start',
                r'video.*init', r'cam.*start'
            ],
            'end_patterns': [
                r'camera.*ready', r'sensor.*ready', r'video.*ready',
                r'preview.*start', r'camera.*online'
            ],
            'related_patterns': [
                r'camera', r'sensor', r'isp', r'lens', r'exposure',
                r'focus', r'resolution', r'preview', r'video'
            ],
            'description': 'Camera sensor initialization'
        }
    }

    def detect_flows(self, entries):
        """
        Detect operational flows in log entries

        Returns list of detected flows with their log entries
        """
        detected_flows = []

        for flow_id, flow_config in self.FLOWS.items():
            flow_entries = self._find_flow_entries(entries, flow_config)

            if flow_entries:
                # Get participating services and components
                services = set()
                components = set()
                severities = defaultdict(int)

                for entry in flow_entries:
                    if entry.get('service'):
                        services.add(entry['service'])
                    if entry.get('component'):
                        components.add(entry['component'])
                    sev = entry.get('severity', 'INFO')
                    severities[sev] += 1

                # Determine if flow has errors
                has_errors = severities.get('ERROR', 0) > 0 or severities.get('CRITICAL', 0) > 0

                # Find flow boundaries
                first_entry = flow_entries[0]
                last_entry = flow_entries[-1]

                detected_flows.append({
                    'id': flow_id,
                    'name': flow_config['name'],
                    'icon': flow_config['icon'],
                    'color': flow_config['color'],
                    'description': flow_config['description'],
                    'entry_count': len(flow_entries),
                    'start_line': first_entry['line_number'],
                    'end_line': last_entry['line_number'],
                    'start_time': first_entry.get('timestamp'),
                    'end_time': last_entry.get('timestamp'),
                    'services': sorted(list(services)),
                    'components': sorted(list(components)),
                    'severities': dict(severities),
                    'has_errors': has_errors,
                    'entries': flow_entries  # All entries in this flow
                })

        # Sort by start line
        detected_flows.sort(key=lambda x: x['start_line'])

        return detected_flows

    def _find_flow_entries(self, entries, flow_config):
        """Find all entries belonging to a specific flow"""
        # Compile patterns
        related_pattern = '|'.join(flow_config['related_patterns'])
        related_regex = re.compile(related_pattern, re.IGNORECASE)

        matching_entries = []

        for entry in entries:
            content = entry.get('raw_content', '') or entry.get('message', '') or ''
            if related_regex.search(content):
                matching_entries.append({
                    'line_number': entry.get('line_number'),
                    'timestamp': entry.get('timestamp'),
                    'severity': entry.get('severity'),
                    'service': entry.get('service'),
                    'component': entry.get('component'),
                    'message': entry.get('message', '')[:200] or content[:200],
                    'raw_content': content[:500]
                })

        return matching_entries

    def get_flow_summary(self, entries):
        """Get summary of all detected flows"""
        flows = self.detect_flows(entries)

        # Calculate statistics
        total_flow_entries = sum(f['entry_count'] for f in flows)
        flows_with_errors = [f for f in flows if f['has_errors']]

        # Get all unique services across all flows
        all_services = set()
        for flow in flows:
            all_services.update(flow['services'])

        return {
            'flows': flows,
            'total_flows': len(flows),
            'total_flow_entries': total_flow_entries,
            'flows_with_errors': len(flows_with_errors),
            'all_services': sorted(list(all_services))
        }
