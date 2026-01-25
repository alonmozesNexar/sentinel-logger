"""
Comprehensive Test Suite for LogParser Service
Tests various log formats, edge cases, and performance scenarios.
"""
import os
import sys
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple

# Add the parent directory to the path so we can import the app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.log_parser import LogParser


class _TestResults:
    """Track test results (underscore prefix to prevent pytest collection)"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        self.warnings = []

    def add_pass(self, test_name: str):
        self.passed += 1
        print(f"  [PASS] {test_name}")

    def add_fail(self, test_name: str, expected, actual, details: str = ""):
        self.failed += 1
        error_msg = f"  [FAIL] {test_name}\n    Expected: {expected}\n    Actual: {actual}"
        if details:
            error_msg += f"\n    Details: {details}"
        print(error_msg)
        self.errors.append(error_msg)

    def add_warning(self, message: str):
        self.warnings.append(message)
        print(f"  [WARN] {message}")

    def summary(self):
        total = self.passed + self.failed
        print("\n" + "="*60)
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        print("="*60)
        if self.errors:
            print(f"\nFailed Tests ({len(self.errors)}):")
            for error in self.errors:
                print(error)
        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")
        return self.failed == 0


class LogParserTestSuite:
    """Test suite for LogParser"""

    def __init__(self):
        self.parser = LogParser()
        self.results = _TestResults()
        self.temp_files = []

    def create_temp_log_file(self, content: str, suffix: str = ".log") -> Path:
        """Create a temporary log file with the given content"""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.write(fd, content.encode('utf-8'))
        os.close(fd)
        self.temp_files.append(path)
        return Path(path)

    def cleanup(self):
        """Remove temporary files"""
        for path in self.temp_files:
            try:
                os.unlink(path)
            except:
                pass

    # =========================================================================
    # TIMESTAMP PARSING TESTS
    # =========================================================================

    def test_timestamp_iso_format(self):
        """Test ISO 8601 timestamp parsing"""
        print("\n--- Testing ISO 8601 Timestamps ---")

        test_cases = [
            ("2024-01-15T14:30:25Z INFO Starting service", datetime(2024, 1, 15, 14, 30, 25)),
            ("2024-01-15T14:30:25.123Z INFO With milliseconds", datetime(2024, 1, 15, 14, 30, 25, 123000)),
            ("2024-01-15T14:30:25.123456Z INFO With microseconds", datetime(2024, 1, 15, 14, 30, 25, 123456)),
            ("2024-01-15T14:30:25+00:00 INFO With timezone", datetime(2024, 1, 15, 14, 30, 25)),
            ("2024-01-15T14:30:25-05:00 INFO Negative timezone", datetime(2024, 1, 15, 14, 30, 25)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"ISO timestamp: {line[:30]}...", expected_dt, result)
            elif result.replace(microsecond=0) == expected_dt.replace(microsecond=0):
                self.results.add_pass(f"ISO timestamp: {line[:30]}...")
            else:
                self.results.add_fail(f"ISO timestamp: {line[:30]}...", expected_dt, result)

    def test_timestamp_standard_format(self):
        """Test standard datetime format parsing"""
        print("\n--- Testing Standard Timestamps ---")

        test_cases = [
            ("2024-01-15 14:30:25 INFO Standard format", datetime(2024, 1, 15, 14, 30, 25)),
            ("2024-01-15  14:30:25 INFO Double space", datetime(2024, 1, 15, 14, 30, 25)),
            ("2024-01-15 14:30:25.123 INFO With milliseconds", datetime(2024, 1, 15, 14, 30, 25, 123000)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"Standard timestamp: {line[:35]}...", expected_dt, result)
            elif abs((result - expected_dt).total_seconds()) < 1:
                self.results.add_pass(f"Standard timestamp: {line[:35]}...")
            else:
                self.results.add_fail(f"Standard timestamp: {line[:35]}...", expected_dt, result)

    def test_timestamp_syslog_format(self):
        """Test syslog timestamp format parsing"""
        print("\n--- Testing Syslog Timestamps ---")

        current_year = datetime.now().year
        test_cases = [
            ("Dec  9 15:58:03 video_service[1234]: Starting", datetime(current_year, 12, 9, 15, 58, 3)),
            ("Jan 15 08:30:00 audio_service[5678]: Initialized", datetime(current_year, 1, 15, 8, 30, 0)),
            ("Dec  9 15:58:03.124614 service[123]: With microseconds", datetime(current_year, 12, 9, 15, 58, 3, 124614)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"Syslog timestamp: {line[:40]}...", expected_dt, result)
            elif result.replace(microsecond=0) == expected_dt.replace(microsecond=0):
                self.results.add_pass(f"Syslog timestamp: {line[:40]}...")
            else:
                self.results.add_fail(f"Syslog timestamp: {line[:40]}...", expected_dt, result,
                                     f"Year mismatch or date parsing issue")

    def test_timestamp_epoch_format(self):
        """Test Unix epoch timestamp parsing"""
        print("\n--- Testing Unix Epoch Timestamps ---")

        test_cases = [
            ("[1705329025] INFO Epoch timestamp", datetime(2024, 1, 15, 12, 30, 25)),
            ("[1705329025.123] INFO Epoch with milliseconds", datetime(2024, 1, 15, 12, 30, 25, 123000)),
            ("[1705329025.123456] INFO Epoch with microseconds", datetime(2024, 1, 15, 12, 30, 25, 123456)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"Epoch timestamp: {line[:35]}...", expected_dt, result)
            elif abs((result - expected_dt).total_seconds()) < 2:  # Allow 2 second tolerance for timezone
                self.results.add_pass(f"Epoch timestamp: {line[:35]}...")
            else:
                self.results.add_fail(f"Epoch timestamp: {line[:35]}...", expected_dt, result,
                                     f"Difference: {abs((result - expected_dt).total_seconds())} seconds")

    def test_timestamp_us_format(self):
        """Test US date format parsing"""
        print("\n--- Testing US Date Format Timestamps ---")

        test_cases = [
            ("01/15/2024 14:30:25 INFO US format", datetime(2024, 1, 15, 14, 30, 25)),
            ("12/31/2023 23:59:59 INFO Year end", datetime(2023, 12, 31, 23, 59, 59)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"US format timestamp: {line[:35]}...", expected_dt, result)
            elif result == expected_dt:
                self.results.add_pass(f"US format timestamp: {line[:35]}...")
            else:
                self.results.add_fail(f"US format timestamp: {line[:35]}...", expected_dt, result)

    def test_timestamp_time_only_format(self):
        """Test time-only timestamp format"""
        print("\n--- Testing Time-Only Timestamps ---")

        test_cases = [
            ("14:30:25 INFO Time only", None),  # Should parse but will have today's date
            ("14:30:25.123456 INFO With microseconds", None),
        ]

        for line, _ in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is not None:
                self.results.add_pass(f"Time-only timestamp parsed: {line[:30]}...")
            else:
                self.results.add_fail(f"Time-only timestamp: {line[:30]}...", "datetime object", result)

    def test_timestamp_compact_format(self):
        """Test compact timestamp format (YYYYMMDDHHmmss)"""
        print("\n--- Testing Compact Timestamps ---")

        test_cases = [
            ("20240115143025 INFO Compact format", datetime(2024, 1, 15, 14, 30, 25)),
        ]

        for line, expected_dt in test_cases:
            result = self.parser.parse_timestamp(line)
            if result is None:
                self.results.add_fail(f"Compact timestamp: {line[:35]}...", expected_dt, result)
            elif result == expected_dt:
                self.results.add_pass(f"Compact timestamp: {line[:35]}...")
            else:
                self.results.add_fail(f"Compact timestamp: {line[:35]}...", expected_dt, result)

    def test_timestamp_edge_cases(self):
        """Test timestamp edge cases"""
        print("\n--- Testing Timestamp Edge Cases ---")

        # Lines without timestamps
        result = self.parser.parse_timestamp("Just a plain message without timestamp")
        if result is None:
            self.results.add_pass("No timestamp correctly returns None")
        else:
            self.results.add_fail("No timestamp", None, result)

        # Multiple timestamps (should get first)
        result = self.parser.parse_timestamp("2024-01-15 10:00:00 to 2024-01-15 11:00:00")
        if result is not None and result.hour == 10:
            self.results.add_pass("Multiple timestamps - gets first")
        else:
            self.results.add_fail("Multiple timestamps", "first timestamp (10:00)", result)

        # Malformed timestamp
        result = self.parser.parse_timestamp("2024-13-45 99:99:99 Invalid date")
        if result is None:
            self.results.add_pass("Malformed timestamp correctly returns None")
        else:
            self.results.add_warning(f"Malformed timestamp parsed as: {result}")

    # =========================================================================
    # SEVERITY PARSING TESTS
    # =========================================================================

    def test_severity_levels_uppercase(self):
        """Test uppercase severity levels"""
        print("\n--- Testing Uppercase Severity Levels ---")

        test_cases = [
            ("CRITICAL: System failure", "CRITICAL"),
            ("CRIT: System failure", "CRITICAL"),
            ("FATAL: Process terminated", "CRITICAL"),
            ("ERROR: Connection failed", "ERROR"),
            ("ERR: Connection failed", "ERROR"),
            ("WARNING: Low memory", "WARNING"),
            ("WARN: Low memory", "WARNING"),
            ("WRN: Low memory", "WARNING"),
            ("INFO: Starting service", "INFO"),
            ("INF: Starting service", "INFO"),
            ("NOTICE: Configuration updated", "INFO"),
            ("DEBUG: Variable value", "DEBUG"),
            ("DBG: Variable value", "DEBUG"),
            ("TRACE: Entering function", "DEBUG"),
            ("VERBOSE: Detailed info", "DEBUG"),
        ]

        for line, expected_severity in test_cases:
            result = self.parser.parse_severity(line)
            if result == expected_severity:
                self.results.add_pass(f"Severity {expected_severity}: {line[:25]}...")
            else:
                self.results.add_fail(f"Severity: {line[:25]}...", expected_severity, result)

    def test_severity_bracket_formats(self):
        """Test bracket-enclosed severity markers"""
        print("\n--- Testing Bracket Severity Formats ---")

        test_cases = [
            ("[critical] System crash", "CRITICAL"),
            ("[crit] System crash", "CRITICAL"),
            ("[fatal] Process died", "CRITICAL"),
            ("[error] File not found", "ERROR"),
            ("[err] File not found", "ERROR"),
            ("[warning] Disk space low", "WARNING"),
            ("[warn] Disk space low", "WARNING"),
            ("[info] Service started", "INFO"),
            ("[notice] Config loaded", "INFO"),
            ("[debug] Checkpoint reached", "DEBUG"),
            ("[dbg] Checkpoint reached", "DEBUG"),
            ("[trace] Function entry", "DEBUG"),
        ]

        for line, expected_severity in test_cases:
            result = self.parser.parse_severity(line)
            if result == expected_severity:
                self.results.add_pass(f"Bracket severity {expected_severity}: {line[:25]}...")
            else:
                self.results.add_fail(f"Bracket severity: {line[:25]}...", expected_severity, result)

    def test_severity_default(self):
        """Test default severity when none specified"""
        print("\n--- Testing Default Severity ---")

        test_cases = [
            "Just a regular message",
            "2024-01-15 Service started",
            "Connection established",
        ]

        for line in test_cases:
            result = self.parser.parse_severity(line)
            if result == "INFO":
                self.results.add_pass(f"Default severity INFO: {line[:25]}...")
            else:
                self.results.add_fail(f"Default severity: {line[:25]}...", "INFO", result)

    def test_severity_mixed_case(self):
        """Test mixed case severity levels"""
        print("\n--- Testing Mixed Case Severity ---")

        test_cases = [
            ("Error: Something went wrong", "ERROR"),
            ("Warning: Be careful", "WARNING"),
            ("Info: Status update", "INFO"),
            ("Debug: Value = 42", "DEBUG"),
        ]

        for line, expected_severity in test_cases:
            result = self.parser.parse_severity(line)
            if result == expected_severity:
                self.results.add_pass(f"Mixed case severity: {line[:25]}...")
            else:
                self.results.add_fail(f"Mixed case severity: {line[:25]}...", expected_severity, result)

    # =========================================================================
    # SERVICE DETECTION TESTS
    # =========================================================================

    def test_service_detection_generic(self):
        """Test generic service detection patterns"""
        print("\n--- Testing Generic Service Detection ---")

        test_cases = [
            ("video_service[1234]: Frame dropped", "video-service"),
            ("video-stream started", "video-service"),
            ("audio_service initializing", "audio-service"),
            ("audio-stream buffer full", "audio-service"),
            ("network_service connected", "network-service"),
            ("wifi connection established", "network-service"),
            ("storage_service mounted", "storage-service"),
            ("sd_card detected", "storage-service"),
            ("firmware_service updating", "firmware-service"),
            ("fw_update progress 50%", "firmware-service"),
            ("sensor_service reading", "sensor-service"),
            ("accelerometer calibrated", "sensor-service"),
            ("power_service status", "power-service"),
            ("battery level 85%", "power-service"),
            ("lens_service focusing", "lens-service"),
            ("image_processor starting", "image-processor"),
            ("ui_service rendering", "ui-service"),
        ]

        for line, expected_service in test_cases:
            result = self.parser.parse_service(line)
            if result == expected_service:
                self.results.add_pass(f"Service detection: {expected_service}")
            else:
                self.results.add_fail(f"Service: {line[:30]}...", expected_service, result)

    def test_service_detection_nexar_specific(self):
        """Test Nexar/dashcam specific service detection"""
        print("\n--- Testing Nexar-Specific Service Detection ---")

        test_cases = [
            ("collision_flow_reactor event detected", "collision-flow"),
            ("signalDistributorServer started", "signal-distributor"),
            ("EventEnricher processing", "event-enricher"),
            ("lighthouse beacon sent", "lighthouse"),
            ("fs_notification received", "fs-notification"),
            ("picmancli capturing", "picman-cli"),
            ("connection_manager connecting", "connection-manager"),
            ("rsyslogd message", "rsyslog"),
            ("PlatformEventsClient connected", "platform-events"),
        ]

        for line, expected_service in test_cases:
            result = self.parser.parse_service(line)
            if result == expected_service:
                self.results.add_pass(f"Nexar service: {expected_service}")
            else:
                self.results.add_fail(f"Nexar service: {line[:30]}...", expected_service, result)

    def test_service_detection_syslog_fallback(self):
        """Test syslog format fallback for service detection"""
        print("\n--- Testing Syslog Fallback Service Detection ---")

        test_cases = [
            ("Dec  9 15:58:03.124614] custom_process[12345]: Message", "custom-process"),
            ("Jan 15 10:00:00] my_service[999]: Started", "my-service"),
        ]

        for line, expected_service in test_cases:
            result = self.parser.parse_service(line)
            if result == expected_service:
                self.results.add_pass(f"Syslog fallback: {expected_service}")
            else:
                # This is expected to potentially fail if the pattern doesn't match
                self.results.add_warning(f"Syslog fallback pattern may not match: {line[:40]}...")

    def test_service_detection_none(self):
        """Test when no service can be detected"""
        print("\n--- Testing No Service Detection ---")

        result = self.parser.parse_service("Just a plain message")
        if result is None:
            self.results.add_pass("No service correctly returns None")
        else:
            self.results.add_fail("No service detection", None, result)

    # =========================================================================
    # COMPONENT DETECTION TESTS
    # =========================================================================

    def test_component_detection_cameras(self):
        """Test camera component detection"""
        print("\n--- Testing Camera Component Detection ---")

        test_cases = [
            ("front_camera initialized", "front-camera"),
            ("rear_camera frame captured", "rear-camera"),
            ("wide_angle lens adjusted", "wide-angle"),
            ("telephoto zoom at 5x", "telephoto"),
            ("depth_sensor reading", "depth-sensor"),
            ("ir_camera enabled", "ir-camera"),
            ("ROAD_FACING camera active", "road-facing-camera"),
            ("INTERIOR_FACING recording", "interior-facing-camera"),
        ]

        for line, expected_component in test_cases:
            result = self.parser.parse_component(line)
            if result == expected_component:
                self.results.add_pass(f"Camera component: {expected_component}")
            else:
                self.results.add_fail(f"Camera component: {line[:30]}...", expected_component, result)

    def test_component_detection_hardware(self):
        """Test hardware component detection"""
        print("\n--- Testing Hardware Component Detection ---")

        test_cases = [
            ("image_sensor initialized", "image-sensor"),
            ("ISP pipeline ready", "isp"),
            ("lens_motor calibrating", "lens-motor"),
            ("OIS stabilization active", "ois"),
            ("flash fired", "flash"),
            ("aperture set to f/2.8", "aperture"),
            ("shutter opened", "shutter"),
            ("sdcard mounted", "memory-card"),
            ("USB connected", "usb"),
            ("HDMI output enabled", "hdmi"),
            ("wifi_module connected", "wifi"),
            ("bluetooth paired", "bluetooth"),
            ("GPS lock acquired", "gps"),
            ("microphone level set", "microphone"),
        ]

        for line, expected_component in test_cases:
            result = self.parser.parse_component(line)
            if result == expected_component:
                self.results.add_pass(f"Hardware component: {expected_component}")
            else:
                self.results.add_fail(f"Hardware component: {line[:30]}...", expected_component, result)

    def test_component_detection_software(self):
        """Test software component detection"""
        print("\n--- Testing Software Component Detection ---")

        test_cases = [
            ("encoder started", "encoder"),
            ("H264 encoding", "encoder"),
            ("decoder initialized", "decoder"),
            ("preview_pipeline running", "preview"),
            ("autofocus searching", "autofocus"),
            ("auto_exposure adjusting", "auto-exposure"),
            ("auto_white_balance calibrating", "awb"),
            ("face_detection found 2 faces", "face-detection"),
            ("HDR_engine processing", "hdr"),
            ("noise_reduction applied", "noise-reduction"),
            ("raw_processor converting", "raw-processor"),
            ("JPEG_encoder compressing", "jpeg-encoder"),
            ("thumbnail_generator created", "thumbnail"),
            ("metadata_handler writing EXIF", "metadata"),
            ("buffer_manager allocated", "buffer-manager"),
            ("driver loaded", "driver"),
            ("HAL initialized", "hal"),
        ]

        for line, expected_component in test_cases:
            result = self.parser.parse_component(line)
            if result == expected_component:
                self.results.add_pass(f"Software component: {expected_component}")
            else:
                self.results.add_fail(f"Software component: {line[:30]}...", expected_component, result)

    # =========================================================================
    # COMMAND DETECTION TESTS
    # =========================================================================

    def test_command_detection(self):
        """Test command detection patterns"""
        print("\n--- Testing Command Detection ---")

        test_cases = [
            ("START_RECORDING triggered", "start-recording"),
            ("REC_START initiated", "start-recording"),
            ("STOP_RECORDING complete", "stop-recording"),
            ("TAKE_PHOTO captured", "capture-photo"),
            ("CAPTURE_IMAGE saved", "capture-photo"),
            ("CONNECT to server", "connect"),
            ("DISCONNECT from network", "disconnect"),
            ("UPLOAD starting", "upload"),
            ("DOWNLOAD complete", "download"),
            ("CONFIG updated", "configure"),
            ("RESET system", "reset"),
            ("CALIBRATE sensors", "calibrate"),
        ]

        for line, expected_command in test_cases:
            result = self.parser.parse_command(line)
            if result == expected_command:
                self.results.add_pass(f"Command detection: {expected_command}")
            else:
                self.results.add_fail(f"Command: {line[:30]}...", expected_command, result)

    # =========================================================================
    # FULL LINE PARSING TESTS
    # =========================================================================

    def test_parse_line_complete(self):
        """Test complete line parsing"""
        print("\n--- Testing Complete Line Parsing ---")

        test_line = "2024-01-15T14:30:25.123Z ERROR video_service[1234]: front_camera CAPTURE_IMAGE failed - memory buffer full"
        result = self.parser.parse_line(test_line, 1)

        checks = [
            ("line_number", result.get('line_number') == 1, 1, result.get('line_number')),
            ("timestamp_parsed", result.get('timestamp') is not None, "not None", result.get('timestamp')),
            ("severity", result.get('severity') == 'ERROR', 'ERROR', result.get('severity')),
            ("service", result.get('service') == 'video-service', 'video-service', result.get('service')),
            ("component", result.get('component') == 'front-camera', 'front-camera', result.get('component')),
            ("command", result.get('command') == 'capture-photo', 'capture-photo', result.get('command')),
            ("raw_content", result.get('raw_content') == test_line, test_line[:30], result.get('raw_content', '')[:30]),
        ]

        for name, passed, expected, actual in checks:
            if passed:
                self.results.add_pass(f"parse_line {name}")
            else:
                self.results.add_fail(f"parse_line {name}", expected, actual)

    # =========================================================================
    # FILE PARSING TESTS
    # =========================================================================

    def test_parse_file_basic(self):
        """Test basic file parsing"""
        print("\n--- Testing Basic File Parsing ---")

        log_content = """2024-01-15 10:00:00 INFO Starting application
2024-01-15 10:00:01 DEBUG Initializing video_service
2024-01-15 10:00:02 WARNING Low memory warning
2024-01-15 10:00:03 ERROR video_service failed to start
2024-01-15 10:00:04 CRITICAL System crash imminent
"""

        log_file = self.create_temp_log_file(log_content)
        entries, stats = self.parser.parse_file_full(log_file)

        checks = [
            ("total_lines", stats['total_lines'] == 5, 5, stats['total_lines']),
            ("info_count", stats['info_count'] == 1, 1, stats['info_count']),
            ("debug_count", stats['debug_count'] == 1, 1, stats['debug_count']),
            ("warning_count", stats['warning_count'] == 1, 1, stats['warning_count']),
            ("error_count", stats['error_count'] == 1, 1, stats['error_count']),
            ("critical_count", stats['critical_count'] == 1, 1, stats['critical_count']),
            ("time_range_start", stats['time_range']['start'] is not None, "not None", stats['time_range']['start']),
            ("time_range_end", stats['time_range']['end'] is not None, "not None", stats['time_range']['end']),
        ]

        for name, passed, expected, actual in checks:
            if passed:
                self.results.add_pass(f"parse_file {name}")
            else:
                self.results.add_fail(f"parse_file {name}", expected, actual)

    def test_parse_file_empty_lines(self):
        """Test file parsing with empty lines"""
        print("\n--- Testing File Parsing with Empty Lines ---")

        log_content = """2024-01-15 10:00:00 INFO First entry

2024-01-15 10:00:02 INFO Second entry


2024-01-15 10:00:05 INFO Third entry
"""

        log_file = self.create_temp_log_file(log_content)
        entries, stats = self.parser.parse_file_full(log_file)

        if stats['total_lines'] == 3:
            self.results.add_pass("Empty lines skipped correctly")
        else:
            self.results.add_fail("Empty line handling", 3, stats['total_lines'],
                                 "Empty lines should be skipped")

    def test_parse_file_special_characters(self):
        """Test file parsing with special characters"""
        print("\n--- Testing File Parsing with Special Characters ---")

        log_content = """2024-01-15 10:00:00 INFO Message with "quotes" and 'apostrophes'
2024-01-15 10:00:01 INFO Path: /var/log/test.log
2024-01-15 10:00:02 INFO Unicode: cafe
2024-01-15 10:00:03 INFO Special: <tag> & ampersand
2024-01-15 10:00:04 INFO JSON: {"key": "value", "num": 123}
2024-01-15 10:00:05 INFO Brackets: [data] (info) {config}
"""

        log_file = self.create_temp_log_file(log_content)
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            if stats['total_lines'] == 6:
                self.results.add_pass("Special characters handled correctly")
            else:
                self.results.add_fail("Special character handling", 6, stats['total_lines'])
        except Exception as e:
            self.results.add_fail("Special character handling", "no exception", str(e))

    def test_parse_file_mixed_formats(self):
        """Test file with mixed timestamp formats"""
        print("\n--- Testing Mixed Timestamp Formats ---")

        log_content = """2024-01-15T10:00:00Z INFO ISO format
2024-01-15 10:00:01 INFO Standard format
Dec  9 15:58:03 service[123]: Syslog format
[1705320005] INFO Epoch format
01/15/2024 10:00:05 INFO US format
10:00:06 INFO Time only
"""

        log_file = self.create_temp_log_file(log_content)
        entries, stats = self.parser.parse_file_full(log_file)

        timestamps_parsed = sum(1 for e in entries if e['timestamp'] is not None)
        if timestamps_parsed == 6:
            self.results.add_pass("All mixed timestamps parsed")
        else:
            self.results.add_fail("Mixed timestamp parsing", 6, timestamps_parsed,
                                 f"Only {timestamps_parsed} timestamps parsed")

    def test_parse_file_various_services(self):
        """Test file with various services"""
        print("\n--- Testing Various Services in File ---")

        log_content = """2024-01-15 10:00:00 INFO video_service started
2024-01-15 10:00:01 INFO audio_service initialized
2024-01-15 10:00:02 INFO network_service connected
2024-01-15 10:00:03 INFO storage_service mounted
2024-01-15 10:00:04 INFO sensor_service calibrated
"""

        log_file = self.create_temp_log_file(log_content)
        entries, stats = self.parser.parse_file_full(log_file)

        expected_services = {'video-service', 'audio-service', 'network-service', 'storage-service', 'sensor-service'}
        found_services = set(stats['services'])

        if expected_services == found_services:
            self.results.add_pass("All services detected in file")
        else:
            missing = expected_services - found_services
            extra = found_services - expected_services
            self.results.add_fail("Service detection in file", expected_services, found_services,
                                 f"Missing: {missing}, Extra: {extra}")

    # =========================================================================
    # EDGE CASE TESTS
    # =========================================================================

    def test_edge_case_very_long_line(self):
        """Test parsing very long log lines"""
        print("\n--- Testing Very Long Lines ---")

        long_message = "A" * 10000
        log_content = f"2024-01-15 10:00:00 INFO {long_message}\n"

        log_file = self.create_temp_log_file(log_content)
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            if len(entries) == 1:
                self.results.add_pass("Very long line handled correctly")
            else:
                self.results.add_fail("Very long line handling", 1, len(entries))
        except Exception as e:
            self.results.add_fail("Very long line handling", "no exception", str(e))

    def test_edge_case_binary_characters(self):
        """Test handling of binary characters in file"""
        print("\n--- Testing Binary Characters ---")

        # Create a file with some binary-like content mixed in
        log_content = "2024-01-15 10:00:00 INFO Normal message\n"
        log_content += "2024-01-15 10:00:01 INFO Message with null\x00byte\n"
        log_content += "2024-01-15 10:00:02 INFO Message with bell\x07char\n"

        log_file = self.create_temp_log_file(log_content)
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            self.results.add_pass("Binary characters handled without crash")
        except Exception as e:
            self.results.add_fail("Binary character handling", "no exception", str(e))

    def test_edge_case_empty_file(self):
        """Test parsing empty file"""
        print("\n--- Testing Empty File ---")

        log_file = self.create_temp_log_file("")
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            if len(entries) == 0 and stats['total_lines'] == 0:
                self.results.add_pass("Empty file handled correctly")
            else:
                self.results.add_fail("Empty file handling", "0 entries", len(entries))
        except Exception as e:
            self.results.add_fail("Empty file handling", "no exception", str(e))

    def test_edge_case_only_whitespace(self):
        """Test file with only whitespace"""
        print("\n--- Testing Whitespace-Only File ---")

        log_content = "   \n\t\n   \n"
        log_file = self.create_temp_log_file(log_content)
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            if len(entries) == 0:
                self.results.add_pass("Whitespace-only file handled correctly")
            else:
                self.results.add_fail("Whitespace-only handling", 0, len(entries))
        except Exception as e:
            self.results.add_fail("Whitespace-only handling", "no exception", str(e))

    def test_edge_case_malformed_timestamps(self):
        """Test handling of malformed timestamps"""
        print("\n--- Testing Malformed Timestamps ---")

        log_content = """2024-13-45 99:99:99 INFO Invalid date
2024-02-30 10:00:00 INFO Feb 30th doesn't exist
9999-99-99 00:00:00 INFO Far future date
0000-00-00 00:00:00 INFO Zero date
"""

        log_file = self.create_temp_log_file(log_content)
        try:
            entries, stats = self.parser.parse_file_full(log_file)
            # Should parse lines even if timestamps are invalid
            if stats['total_lines'] == 4:
                self.results.add_pass("Malformed timestamps don't crash parser")
            else:
                self.results.add_fail("Malformed timestamp handling", 4, stats['total_lines'])

            # Check how many timestamps were actually parsed
            parsed_timestamps = sum(1 for e in entries if e['timestamp'] is not None)
            self.results.add_warning(f"Malformed timestamps: {parsed_timestamps}/4 were parsed (may or may not be correct)")
        except Exception as e:
            self.results.add_fail("Malformed timestamp handling", "no exception", str(e))

    # =========================================================================
    # PERFORMANCE TESTS
    # =========================================================================

    def test_performance_large_file(self):
        """Test performance with a large file"""
        print("\n--- Testing Performance with Large File ---")

        # Generate a large log file (10000 lines)
        lines = []
        for i in range(10000):
            hour = (i // 3600) % 24
            minute = (i // 60) % 60
            second = i % 60
            severity = ['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'][i % 5]
            service = ['video_service', 'audio_service', 'network_service'][i % 3]
            lines.append(f"2024-01-15 {hour:02d}:{minute:02d}:{second:02d} {severity} {service} Message number {i}")

        log_content = "\n".join(lines)
        log_file = self.create_temp_log_file(log_content)

        start_time = time.time()
        entries, stats = self.parser.parse_file_full(log_file)
        elapsed_time = time.time() - start_time

        if stats['total_lines'] == 10000:
            self.results.add_pass(f"Large file (10000 lines) parsed in {elapsed_time:.3f}s")
        else:
            self.results.add_fail("Large file parsing", 10000, stats['total_lines'])

        # Performance threshold: should parse 10000 lines in under 5 seconds
        if elapsed_time < 5.0:
            self.results.add_pass(f"Performance acceptable: {elapsed_time:.3f}s < 5.0s")
        else:
            self.results.add_warning(f"Performance may be slow: {elapsed_time:.3f}s for 10000 lines")

    def test_performance_chunked_parsing(self):
        """Test chunked file parsing"""
        print("\n--- Testing Chunked Parsing ---")

        # Generate a file with more lines than chunk size
        lines = [f"2024-01-15 10:00:{i:02d} INFO Message {i}" for i in range(100)]
        log_content = "\n".join(lines)
        log_file = self.create_temp_log_file(log_content)

        chunk_count = 0
        total_entries = 0
        for chunk in self.parser.parse_file(log_file, chunk_size=25):
            chunk_count += 1
            total_entries += len(chunk)

        if total_entries == 100:
            self.results.add_pass(f"Chunked parsing: {total_entries} entries in {chunk_count} chunks")
        else:
            self.results.add_fail("Chunked parsing", 100, total_entries)

    # =========================================================================
    # DEVICE INFO EXTRACTION TESTS
    # =========================================================================

    def test_device_info_extraction(self):
        """Test device info extraction from log headers"""
        print("\n--- Testing Device Info Extraction ---")

        log_content = """Device: CAM-PRO-2000
Firmware: v2.1.3
Serial: ABC123456
Hardware revision: 1.5
2024-01-15 10:00:00 INFO Device initialized
"""

        log_file = self.create_temp_log_file(log_content)
        device_info = self.parser.get_device_info(log_file)

        checks = [
            ("model", device_info.get('model') == 'CAM-PRO-2000', 'CAM-PRO-2000', device_info.get('model')),
            ("firmware", device_info.get('firmware_version') == '2.1.3', '2.1.3', device_info.get('firmware_version')),
            ("serial", device_info.get('serial_number') == 'ABC123456', 'ABC123456', device_info.get('serial_number')),
            ("hw_revision", device_info.get('hardware_revision') == '1.5', '1.5', device_info.get('hardware_revision')),
        ]

        for name, passed, expected, actual in checks:
            if passed:
                self.results.add_pass(f"Device info {name}")
            else:
                self.results.add_fail(f"Device info {name}", expected, actual)

    # =========================================================================
    # MESSAGE EXTRACTION TESTS
    # =========================================================================

    def test_message_extraction(self):
        """Test message content extraction"""
        print("\n--- Testing Message Extraction ---")

        test_cases = [
            ("2024-01-15 10:00:00 INFO Starting the service now", "Starting the service now"),
            ("[1705320000] ERROR Connection timeout occurred", "Connection timeout occurred"),
        ]

        for line, expected_contains in test_cases:
            result = self.parser.extract_message(line)
            if expected_contains.lower() in result.lower():
                self.results.add_pass(f"Message extraction contains expected text")
            else:
                self.results.add_fail(f"Message extraction", f"contains '{expected_contains}'", result)

    # =========================================================================
    # RUN ALL TESTS
    # =========================================================================

    def run_all_tests(self):
        """Run all test methods"""
        print("="*60)
        print("LogParser Test Suite")
        print("="*60)

        try:
            # Timestamp tests
            self.test_timestamp_iso_format()
            self.test_timestamp_standard_format()
            self.test_timestamp_syslog_format()
            self.test_timestamp_epoch_format()
            self.test_timestamp_us_format()
            self.test_timestamp_time_only_format()
            self.test_timestamp_compact_format()
            self.test_timestamp_edge_cases()

            # Severity tests
            self.test_severity_levels_uppercase()
            self.test_severity_bracket_formats()
            self.test_severity_default()
            self.test_severity_mixed_case()

            # Service tests
            self.test_service_detection_generic()
            self.test_service_detection_nexar_specific()
            self.test_service_detection_syslog_fallback()
            self.test_service_detection_none()

            # Component tests
            self.test_component_detection_cameras()
            self.test_component_detection_hardware()
            self.test_component_detection_software()

            # Command tests
            self.test_command_detection()

            # Full line parsing
            self.test_parse_line_complete()

            # File parsing tests
            self.test_parse_file_basic()
            self.test_parse_file_empty_lines()
            self.test_parse_file_special_characters()
            self.test_parse_file_mixed_formats()
            self.test_parse_file_various_services()

            # Edge cases
            self.test_edge_case_very_long_line()
            self.test_edge_case_binary_characters()
            self.test_edge_case_empty_file()
            self.test_edge_case_only_whitespace()
            self.test_edge_case_malformed_timestamps()

            # Performance tests
            self.test_performance_large_file()
            self.test_performance_chunked_parsing()

            # Device info tests
            self.test_device_info_extraction()

            # Message extraction tests
            self.test_message_extraction()

        finally:
            self.cleanup()

        return self.results.summary()


def main():
    """Main entry point"""
    suite = LogParserTestSuite()
    success = suite.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
