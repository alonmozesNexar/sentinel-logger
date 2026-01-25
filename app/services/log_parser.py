"""
Log Parser Service - Handles parsing of various log formats for camera/hardware logs
"""
import re
from datetime import datetime
from typing import Dict, List, Optional, Generator, Tuple
from pathlib import Path
import chardet


class LogParser:
    """
    Parses log files and extracts structured information.
    Supports multiple common log formats used in camera/hardware testing.
    """

    # Common timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO format: 2024-01-15T14:30:25.123Z
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)', '%Y-%m-%dT%H:%M:%S'),
        # Standard: 2024-01-15 14:30:25.123
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)', '%Y-%m-%d %H:%M:%S'),
        # Syslog format: Dec  9 15:58:03.124614 (month day time)
        (r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)', 'syslog'),
        # US format: 01/15/2024 14:30:25
        (r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})', '%m/%d/%Y %H:%M:%S'),
        # Unix epoch in brackets: [1705329025.123]
        (r'\[(\d{10}(?:\.\d{1,6})?)\]', 'epoch'),
        # Time only with milliseconds: 14:30:25.123
        (r'(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)', '%H:%M:%S'),
        # Compact format: 20240115143025
        (r'(\d{14})', '%Y%m%d%H%M%S'),
    ]

    # Severity level patterns - bracket formats checked FIRST (more explicit)
    SEVERITY_PATTERNS = [
        # Bracket formats are most explicit - check these first
        (r'\[(crit|critical|fatal)\]', 'CRITICAL'),
        (r'\[(err|error)\]', 'ERROR'),
        (r'\[(warn|warning)\]', 'WARNING'),
        (r'\[(notice)\]', 'INFO'),
        (r'\[(info)\]', 'INFO'),
        (r'\[(debug|dbg|trace)\]', 'DEBUG'),
        # Then check keyword patterns
        (r'\b(CRITICAL|CRIT|FATAL)\b', 'CRITICAL'),
        (r'\b(ERROR|ERR)\b', 'ERROR'),  # Removed FAIL/FAILED - too many false positives
        (r'\b(WARNING|WARN|WRN)\b', 'WARNING'),
        (r'\b(INFO|INF|NOTICE)\b', 'INFO'),
        (r'\b(DEBUG|DBG|TRACE|VERBOSE)\b', 'DEBUG'),
    ]

    # Camera/Hardware specific service patterns
    SERVICE_PATTERNS = [
        # Nexar/Dashcam specific services (extracted from process name)
        (r'\bcollision_flow_reactor\b', 'collision-flow'),
        (r'\bsignalDistributorServer\b', 'signal-distributor'),
        (r'\bEventEnricher\b', 'event-enricher'),
        (r'\blighthouse\b', 'lighthouse'),
        (r'\bfs_notification\b', 'fs-notification'),
        (r'\bpicmancli\b', 'picman-cli'),
        (r'\bconnection_manager\b', 'connection-manager'),
        (r'\brsyslogd\b', 'rsyslog'),
        (r'\bPlatformEventsClient\b', 'platform-events'),
        # Generic service patterns
        (r'\b(video[_-]?service|video[_-]?stream|video[_-]?capture|cam[_-]?video)\b', 'video-service'),
        (r'\b(audio[_-]?service|audio[_-]?stream|mic[_-]?service|sound)\b', 'audio-service'),
        (r'\b(network[_-]?service|net[_-]?service|wifi|ethernet|connectivity)\b', 'network-service'),
        (r'\b(storage[_-]?service|disk|sd[_-]?card|memory[_-]?card|file[_-]?system)\b', 'storage-service'),
        (r'\b(firmware[_-]?service|fw[_-]?update|bootloader|system[_-]?update)\b', 'firmware-service'),
        (r'\b(sensor[_-]?service|imu|accelerometer|gyroscope|temperature)\b', 'sensor-service'),
        (r'\b(power[_-]?service|battery|charging|power[_-]?management)\b', 'power-service'),
        (r'\b(lens[_-]?service|focus|zoom|aperture|optical)\b', 'lens-service'),
        (r'\b(image[_-]?processor|isp|image[_-]?pipeline|codec)\b', 'image-processor'),
        (r'\b(ui[_-]?service|display|lcd|screen|gui)\b', 'ui-service'),
    ]

    # Component patterns - specific hardware/software components
    COMPONENT_PATTERNS = [
        # Dashcam/Nexar specific components
        (r'\bROAD_FACING\b', 'road-facing-camera'),
        (r'\bINTERIOR_FACING\b', 'interior-facing-camera'),
        (r'\bFileCreatedEvent\b', 'file-created'),
        (r'\bFileRelatedEvent\b', 'file-event'),
        (r'\bmmcblk0p1\b', 'sd-card'),
        (r'\bvideo_full_ride\b', 'video-storage'),
        (r'\blteRegistrationStatus\b', 'lte-modem'),
        (r'\binternetAccess\b', 'internet'),
        (r'\bsignalQuality\b', 'signal-quality'),
        (r'\bbacklog\b', 'event-backlog'),
        (r'\bpyramid frame\b', 'frame-capture'),
        (r'\bJPEG\b', 'jpeg-processor'),
        (r'\bNV12\b', 'video-format'),
        (r'\bYUV\b', 'video-format'),
        (r'\bChannel:\s*\d+', 'video-channel'),
        # Camera modules
        (r'\b(front[_-]?camera|front[_-]?cam|fcam)\b', 'front-camera'),
        (r'\b(rear[_-]?camera|rear[_-]?cam|rcam|main[_-]?camera)\b', 'rear-camera'),
        (r'\b(wide[_-]?angle|ultra[_-]?wide|wide[_-]?cam)\b', 'wide-angle'),
        (r'\b(telephoto|tele[_-]?cam|zoom[_-]?cam)\b', 'telephoto'),
        (r'\b(depth[_-]?sensor|tof|time[_-]?of[_-]?flight)\b', 'depth-sensor'),
        (r'\b(ir[_-]?camera|infrared|night[_-]?vision)\b', 'ir-camera'),

        # Hardware components
        (r'\b(image[_-]?sensor|cmos|ccd|sensor[_-]?module)\b', 'image-sensor'),
        (r'\b(isp|image[_-]?signal[_-]?processor)\b', 'isp'),
        (r'\b(lens[_-]?motor|vcm|voice[_-]?coil|af[_-]?motor)\b', 'lens-motor'),
        (r'\b(ois|optical[_-]?stabilization|stabilizer)\b', 'ois'),
        (r'\b(flash|led[_-]?flash|strobe)\b', 'flash'),
        (r'\b(aperture|iris|diaphragm)\b', 'aperture'),
        (r'\b(shutter|mechanical[_-]?shutter)\b', 'shutter'),
        (r'\b(viewfinder|evf|ovf)\b', 'viewfinder'),
        (r'\b(lcd|display[_-]?panel|screen[_-]?module)\b', 'display'),
        (r'\b(sdcard|sd[_-]?card|memory[_-]?card|cfexpress)\b', 'memory-card'),
        (r'\b(battery[_-]?module|power[_-]?cell)\b', 'battery'),
        (r'\b(usb|usb[_-]?controller|type[_-]?c)\b', 'usb'),
        (r'\b(hdmi|hdmi[_-]?out|video[_-]?out)\b', 'hdmi'),
        (r'\b(wifi[_-]?module|wlan|wireless)\b', 'wifi'),
        (r'\b(bluetooth|bt[_-]?module|ble)\b', 'bluetooth'),
        (r'\b(gps|gnss|location[_-]?module)\b', 'gps'),
        (r'\b(microphone|mic[_-]?array|audio[_-]?input)\b', 'microphone'),
        (r'\b(speaker|audio[_-]?output)\b', 'speaker'),

        # Software/Pipeline components
        (r'\b(encoder|h264|h265|hevc|avc|video[_-]?encoder)\b', 'encoder'),
        (r'\b(decoder|video[_-]?decoder)\b', 'decoder'),
        (r'\b(preview[_-]?pipeline|preview[_-]?stream)\b', 'preview'),
        (r'\b(capture[_-]?pipeline|capture[_-]?engine)\b', 'capture-pipeline'),
        (r'\b(autofocus|af[_-]?engine|af[_-]?algorithm)\b', 'autofocus'),
        (r'\b(auto[_-]?exposure|ae[_-]?engine|ae[_-]?algorithm)\b', 'auto-exposure'),
        (r'\b(auto[_-]?white[_-]?balance|awb)\b', 'awb'),
        (r'\b(face[_-]?detection|fd[_-]?engine)\b', 'face-detection'),
        (r'\b(hdr[_-]?engine|hdr[_-]?processing|hdr[_-]?merge)\b', 'hdr'),
        (r'\b(noise[_-]?reduction|denoise|nr[_-]?engine)\b', 'noise-reduction'),
        (r'\b(raw[_-]?processor|raw[_-]?converter|dng)\b', 'raw-processor'),
        (r'\b(jpeg[_-]?encoder|jpg[_-]?compression)\b', 'jpeg-encoder'),
        (r'\b(thumbnail[_-]?generator|thumb[_-]?engine)\b', 'thumbnail'),
        (r'\b(metadata[_-]?handler|exif|xmp)\b', 'metadata'),
        (r'\b(buffer[_-]?manager|frame[_-]?buffer|memory[_-]?pool)\b', 'buffer-manager'),
        (r'\b(driver|kernel[_-]?driver|device[_-]?driver)\b', 'driver'),
        (r'\b(hal|hardware[_-]?abstraction)\b', 'hal'),
        (r'\b(framework|camera[_-]?framework|cam[_-]?framework)\b', 'framework'),
    ]

    # Command patterns for camera operations
    COMMAND_PATTERNS = [
        (r'\b(START[_-]?RECORDING|REC[_-]?START|BEGIN[_-]?CAPTURE)\b', 'start-recording'),
        (r'\b(STOP[_-]?RECORDING|REC[_-]?STOP|END[_-]?CAPTURE)\b', 'stop-recording'),
        (r'\b(TAKE[_-]?PHOTO|CAPTURE[_-]?IMAGE|SNAPSHOT)\b', 'capture-photo'),
        (r'\b(CONNECT|INIT[_-]?CONNECTION|ESTABLISH)\b', 'connect'),
        (r'\b(DISCONNECT|CLOSE[_-]?CONNECTION|TERMINATE)\b', 'disconnect'),
        (r'\b(UPLOAD|SYNC|TRANSFER)\b', 'upload'),
        (r'\b(DOWNLOAD|FETCH|RETRIEVE)\b', 'download'),
        (r'\b(CONFIG|CONFIGURE|SETTINGS|SET[_-]?PARAM)\b', 'configure'),
        (r'\b(RESET|RESTART|REBOOT)\b', 'reset'),
        (r'\b(CALIBRATE|CALIBRATION)\b', 'calibrate'),
    ]

    def __init__(self):
        # Compile regex patterns for performance
        self.timestamp_regexes = [(re.compile(p, re.IGNORECASE), fmt) for p, fmt in self.TIMESTAMP_PATTERNS]
        self.severity_regexes = [(re.compile(p, re.IGNORECASE), sev) for p, sev in self.SEVERITY_PATTERNS]
        self.service_regexes = [(re.compile(p, re.IGNORECASE), svc) for p, svc in self.SERVICE_PATTERNS]
        self.component_regexes = [(re.compile(p, re.IGNORECASE), comp) for p, comp in self.COMPONENT_PATTERNS]
        self.command_regexes = [(re.compile(p, re.IGNORECASE), cmd) for p, cmd in self.COMMAND_PATTERNS]

    def detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding"""
        with open(file_path, 'rb') as f:
            raw_data = f.read(10000)  # Read first 10KB for detection
            result = chardet.detect(raw_data)
            return result.get('encoding', 'utf-8') or 'utf-8'

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line"""
        for regex, fmt in self.timestamp_regexes:
            match = regex.search(line)
            if match:
                timestamp_str = match.group(1)
                try:
                    if fmt == 'epoch':
                        return datetime.fromtimestamp(float(timestamp_str))
                    elif fmt == 'syslog':
                        # Syslog format: Dec  9 15:58:03.124614
                        # Add current year since syslog doesn't include it
                        current_year = datetime.now().year
                        timestamp_str = timestamp_str.replace('  ', ' ')  # Normalize spaces
                        if '.' in timestamp_str:
                            base, micro = timestamp_str.rsplit('.', 1)
                            micro = micro[:6].ljust(6, '0')
                            dt = datetime.strptime(f"{current_year} {base}", '%Y %b %d %H:%M:%S')
                            return dt.replace(microsecond=int(micro))
                        return datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                    else:
                        # Clean up the timestamp string
                        timestamp_str = timestamp_str.replace('Z', '').replace('T', ' ')
                        # Handle microseconds
                        if '.' in timestamp_str:
                            base, micro = timestamp_str.rsplit('.', 1)
                            micro = micro[:6].ljust(6, '0')
                            return datetime.strptime(base, fmt.replace('.%f', '')).replace(
                                microsecond=int(micro))
                        return datetime.strptime(timestamp_str.strip(), fmt)
                except (ValueError, OverflowError):
                    continue
        return None

    def parse_severity(self, line: str) -> str:
        """Extract severity level from log line"""
        for regex, severity in self.severity_regexes:
            if regex.search(line):
                return severity
        return 'INFO'  # Default severity

    def parse_service(self, line: str) -> Optional[str]:
        """Extract service name from log line"""
        for regex, service in self.service_regexes:
            if regex.search(line):
                return service
        # Fallback: try to extract process name from syslog format: process_name[pid]:
        match = re.search(r'\]\s+(\w+)\[(\d+)\]:', line)
        if match:
            return match.group(1).lower().replace('_', '-')
        return None

    def parse_command(self, line: str) -> Optional[str]:
        """Extract command type from log line"""
        for regex, command in self.command_regexes:
            if regex.search(line):
                return command
        return None

    def parse_component(self, line: str) -> Optional[str]:
        """Extract component from log line (hardware/software module)"""
        for regex, component in self.component_regexes:
            if regex.search(line):
                return component
        return None

    def extract_message(self, line: str) -> str:
        """Extract the main message content from a log line"""
        # Remove common prefixes like timestamps and severity markers
        message = line

        # Remove timestamp patterns
        for regex, _ in self.timestamp_regexes:
            message = regex.sub('', message)

        # Remove common log format markers like [INFO], <WARNING>, etc.
        message = re.sub(r'[\[\]<>]', ' ', message)

        # Remove severity words (they're captured separately)
        for regex, _ in self.severity_regexes:
            message = regex.sub('', message)

        # Clean up whitespace
        message = ' '.join(message.split())

        return message.strip() or line.strip()

    def parse_line(self, line: str, line_number: int) -> Dict:
        """Parse a single log line into structured data"""
        return {
            'line_number': line_number,
            'timestamp': self.parse_timestamp(line),
            'severity': self.parse_severity(line),
            'service': self.parse_service(line),
            'component': self.parse_component(line),
            'command': self.parse_command(line),
            'message': self.extract_message(line),
            'raw_content': line.rstrip('\n\r')
        }

    def parse_file(self, file_path: Path, chunk_size: int = 10000) -> Generator[List[Dict], None, None]:
        """
        Parse a log file in chunks for memory efficiency.
        Yields lists of parsed entries.
        """
        encoding = self.detect_encoding(file_path)
        chunk = []
        line_number = 0

        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            for line in f:
                line_number += 1
                if line.strip():  # Skip empty lines
                    parsed = self.parse_line(line, line_number)
                    chunk.append(parsed)

                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []

        if chunk:  # Yield remaining entries
            yield chunk

    def parse_file_full(self, file_path: Path) -> Tuple[List[Dict], Dict]:
        """
        Parse entire file and return all entries plus summary statistics.
        Use for smaller files that fit in memory.
        """
        all_entries = []
        stats = {
            'total_lines': 0,
            'error_count': 0,
            'warning_count': 0,
            'info_count': 0,
            'debug_count': 0,
            'critical_count': 0,
            'services': set(),
            'components': set(),
            'commands': set(),
            'time_range': {'start': None, 'end': None}
        }

        for chunk in self.parse_file(file_path):
            for entry in chunk:
                all_entries.append(entry)
                stats['total_lines'] += 1

                # Count by severity
                severity = entry['severity']
                if severity == 'CRITICAL':
                    stats['critical_count'] += 1
                elif severity == 'ERROR':
                    stats['error_count'] += 1
                elif severity == 'WARNING':
                    stats['warning_count'] += 1
                elif severity == 'INFO':
                    stats['info_count'] += 1
                elif severity == 'DEBUG':
                    stats['debug_count'] += 1

                # Track services, components, and commands
                if entry['service']:
                    stats['services'].add(entry['service'])
                if entry['component']:
                    stats['components'].add(entry['component'])
                if entry['command']:
                    stats['commands'].add(entry['command'])

                # Track time range
                if entry['timestamp']:
                    if not stats['time_range']['start'] or entry['timestamp'] < stats['time_range']['start']:
                        stats['time_range']['start'] = entry['timestamp']
                    if not stats['time_range']['end'] or entry['timestamp'] > stats['time_range']['end']:
                        stats['time_range']['end'] = entry['timestamp']

        # Convert sets to lists for JSON serialization
        stats['services'] = list(stats['services'])
        stats['components'] = list(stats['components'])
        stats['commands'] = list(stats['commands'])

        return all_entries, stats

    def get_device_info(self, file_path: Path) -> Dict:
        """
        Attempt to extract device/camera information from log file.
        Looks for common metadata patterns in log headers.
        """
        device_info = {
            'model': None,
            'firmware_version': None,
            'serial_number': None,
            'hardware_revision': None
        }

        patterns = {
            'model': [
                r'(?:device|camera|model)[:\s]+([A-Z0-9\-_]+)',
                r'(?:product)[:\s]+([A-Z0-9\-_]+)'
            ],
            'firmware_version': [
                r'(?:firmware|fw|version)[:\s]+v?(\d+\.\d+(?:\.\d+)?)',
                r'(?:build)[:\s]+([A-Z0-9\.\-_]+)'
            ],
            'serial_number': [
                r'(?:serial|sn)[:\s]+([A-Z0-9\-]+)',
                r'(?:device[_-]?id)[:\s]+([A-Z0-9\-]+)'
            ],
            'hardware_revision': [
                r'(?:hardware|hw)[_\s]?(?:rev|revision)[:\s]+([A-Z0-9\.]+)'
            ]
        }

        encoding = self.detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            # Only check first 100 lines for device info
            for i, line in enumerate(f):
                if i > 100:
                    break

                for field, field_patterns in patterns.items():
                    if device_info[field]:
                        continue
                    for pattern in field_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            device_info[field] = match.group(1)
                            break

        return device_info
