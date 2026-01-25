"""
Issue Detector Service - Automatically detects issues and anomalies in log files
Enhanced with plain English explanations and suggested actions for all skill levels
"""
import re
from collections import defaultdict
from typing import Dict, List


class IssueDetector:
    """
    Analyzes parsed log entries to detect issues, patterns, and anomalies.
    Uses rule-based detection with confidence scoring.
    Provides explanations suitable for beginners and experts.
    """

    # Error patterns with descriptions, severity, explanations and actions
    ERROR_PATTERNS = [
        # Dashcam/Nexar specific patterns
        {
            'pattern': r'(Connection reset by peer|connection ended due to error)',
            'category': 'connection',
            'severity': 'MEDIUM',
            'title_template': 'Connection Reset/Dropped',
            'description': 'Network connection was unexpectedly closed',
            'confidence': 0.9,
            'explanation': 'A network connection between services was dropped. This can happen during normal operation but frequent occurrences indicate a problem.',
            'why_it_matters': 'Frequent connection resets can cause data loss, delayed uploads, or service communication failures.',
            'suggested_actions': [
                'Check if this happens consistently or intermittently',
                'Note the frequency of these resets',
                'Check network/LTE signal strength',
                'Verify if data is still being uploaded successfully'
            ],
            'technical_details': 'Connection reset by peer (error 104) indicates the remote end forcibly closed the connection.'
        },
        {
            'pattern': r'(re-establishing connection|reconnect|retrying connection)',
            'category': 'retry',
            'severity': 'LOW',
            'title_template': 'Service Reconnection Attempt',
            'description': 'Service is attempting to reconnect',
            'confidence': 0.8,
            'explanation': 'A service lost its connection and is trying to reconnect. Occasional reconnects are normal, but frequent ones indicate instability.',
            'why_it_matters': 'Frequent reconnection attempts waste resources and may indicate underlying connectivity issues.',
            'suggested_actions': [
                'Count how many reconnection attempts happen per minute',
                'Check if reconnections eventually succeed',
                'Correlate with signal strength readings'
            ],
            'technical_details': 'Automatic reconnection is a recovery mechanism. High frequency suggests persistent connectivity problems.'
        },
        {
            'pattern': r'(Error receiving|Error sending|Error processing)',
            'category': 'communication',
            'severity': 'HIGH',
            'title_template': 'Service Communication Error',
            'description': 'Error during inter-service communication',
            'confidence': 0.9,
            'explanation': 'Two parts of the camera system had trouble talking to each other.',
            'why_it_matters': 'Communication errors between services can cause features to fail or data to be lost.',
            'suggested_actions': [
                'Identify which services are having communication issues',
                'Check if errors are one-way or bidirectional',
                'Note if errors coincide with specific operations'
            ],
            'technical_details': 'Inter-process communication errors may indicate service crashes, resource exhaustion, or protocol issues.'
        },
        {
            'pattern': r'(signal.*weak|rssi.*-[89]\d|signalQuality.*[0-5],)',
            'category': 'signal',
            'severity': 'MEDIUM',
            'title_template': 'Weak Signal Detected',
            'description': 'Network signal strength is low',
            'confidence': 0.85,
            'explanation': 'The cellular/network signal is weak, which can affect cloud uploads and connectivity.',
            'why_it_matters': 'Weak signal leads to slow or failed uploads, dropped connections, and poor real-time features.',
            'suggested_actions': [
                'Note the location where weak signal occurs',
                'Check if signal improves in different areas',
                'Verify antenna connection if applicable'
            ],
            'technical_details': 'RSSI below -85 dBm typically indicates poor signal. Quality values below 10 are concerning.'
        },
        {
            'pattern': r'(consumer lag:\s*[5-9]\d|consumer lag:\s*[1-9]\d\d)',
            'category': 'performance',
            'severity': 'HIGH',
            'title_template': 'Event Processing Backlog',
            'description': 'Event queue is backing up - processing cannot keep up',
            'confidence': 0.9,
            'explanation': 'The system is generating events faster than it can process them, creating a backlog.',
            'why_it_matters': 'Large backlogs can cause delayed uploads, memory issues, and eventually data loss.',
            'suggested_actions': [
                'Monitor if backlog grows or stabilizes',
                'Check CPU/memory usage',
                'Identify which event types are most common'
            ],
            'technical_details': 'Consumer lag > 50 indicates the consumer cannot keep pace with the producer.'
        },
        {
            'pattern': r'(Write speed degraded|write.*slow|storage.*slow)',
            'category': 'storage',
            'severity': 'HIGH',
            'title_template': 'SD Card Write Speed Issue',
            'description': 'Storage write performance is degraded',
            'confidence': 0.9,
            'explanation': 'The SD card is writing data slower than expected, which can affect recording quality.',
            'why_it_matters': 'Slow write speeds can cause frame drops, recording failures, or corrupted files.',
            'suggested_actions': [
                'Check SD card health and age',
                'Verify SD card speed class (V30/U3 recommended)',
                'Try a different SD card',
                'Check if card is nearly full'
            ],
            'technical_details': '4K recording typically requires 30+ MB/s sustained write. Degraded speed below this causes issues.'
        },
        # Critical issues
        {
            'pattern': r'(crash|segfault|segmentation\s*fault|core\s*dump|panic|kernel\s*panic)',
            'category': 'crash',
            'severity': 'CRITICAL',
            'title_template': 'Application Crash Detected',
            'description': 'A crash or segmentation fault occurred',
            'confidence': 0.95,
            'explanation': 'The camera software unexpectedly stopped working. This is like when an app on your phone suddenly closes - the camera had to restart part of its system.',
            'why_it_matters': 'Crashes can cause lost recordings, missed photos, and poor user experience. If crashes happen often, customers will be frustrated.',
            'suggested_actions': [
                'Note what the camera was doing just before the crash',
                'Check if this crash happens consistently with certain settings',
                'Document the firmware version and camera model',
                'Try to reproduce the crash 3 times to confirm it is repeatable'
            ],
            'technical_details': 'Segmentation faults occur when software tries to access memory it should not. This often indicates a bug in the firmware code.'
        },
        {
            'pattern': r'(out\s*of\s*memory|oom|memory\s*exhausted|malloc\s*failed|alloc\s*fail)',
            'category': 'memory',
            'severity': 'CRITICAL',
            'title_template': 'Memory Exhaustion',
            'description': 'System ran out of memory',
            'confidence': 0.95,
            'explanation': 'The camera ran out of working memory (RAM). Think of it like your desk getting too cluttered - there is no more space to work.',
            'why_it_matters': 'When memory runs out, the camera cannot process new data properly. This can cause recording failures, slow performance, or crashes.',
            'suggested_actions': [
                'Note what features were running when this happened',
                'Check if multiple features were active simultaneously',
                'Test with simpler recording settings (lower resolution)',
                'Report if this happens during normal use vs. stress testing'
            ],
            'technical_details': 'Memory exhaustion suggests either a memory leak in the firmware or the camera is being pushed beyond its hardware limits.'
        },
        {
            'pattern': r'(data\s*loss|corruption|corrupt|file\s*damaged|checksum\s*error)',
            'category': 'data_integrity',
            'severity': 'CRITICAL',
            'title_template': 'Data Corruption Detected',
            'description': 'Data integrity issue detected',
            'confidence': 0.9,
            'explanation': 'Some saved data (like a video or photo) got scrambled or damaged. The file may not open correctly or might look glitchy.',
            'why_it_matters': 'This is a serious issue - customers could lose important memories. Corrupted files may be unrecoverable.',
            'suggested_actions': [
                'Save the corrupted file for developer analysis',
                'Note the SD card brand and model being used',
                'Check if the SD card is nearly full',
                'Test with a different SD card to rule out card issues',
                'Document the exact steps that led to corruption'
            ],
            'technical_details': 'Data corruption can stem from SD card issues, power interruptions during write, or firmware bugs in the file system handler.'
        },

        # High severity issues
        {
            'pattern': r'(timeout|timed?\s*out|deadline\s*exceeded|request\s*timeout)',
            'category': 'timeout',
            'severity': 'HIGH',
            'title_template': 'Operation Timeout',
            'description': 'An operation timed out',
            'confidence': 0.9,
            'explanation': 'Something took too long and the camera gave up waiting. Like when a website takes forever to load and you get an error.',
            'why_it_matters': 'Timeouts can cause features to fail or become unresponsive. Users may think the camera is broken.',
            'suggested_actions': [
                'Note which feature was being used when timeout occurred',
                'Check if WiFi signal is strong (for network timeouts)',
                'Test if SD card is slow (for storage timeouts)',
                'Document if this is intermittent or consistent'
            ],
            'technical_details': 'Timeouts indicate either slow hardware response, network issues, or operations that exceed expected duration limits.'
        },
        {
            'pattern': r'(connection\s*(failed|refused|reset|closed)|cannot\s*connect|network\s*unreachable)',
            'category': 'connection',
            'severity': 'HIGH',
            'title_template': 'Connection Failure',
            'description': 'Network connection failed',
            'confidence': 0.9,
            'explanation': 'The camera could not connect to WiFi or the cloud server. Like when your phone loses signal.',
            'why_it_matters': 'Connection failures prevent uploads, remote control features, and live streaming from working.',
            'suggested_actions': [
                'Verify the WiFi network is working with other devices',
                'Check the WiFi signal strength at the camera location',
                'Note if this happens with specific networks or all networks',
                'Test if the camera can connect to a mobile hotspot'
            ],
            'technical_details': 'Connection failures may indicate WiFi antenna issues, router compatibility problems, or cloud service outages.'
        },
        {
            'pattern': r'(recording\s*failed|capture\s*error|frame\s*drop|video\s*error)',
            'category': 'recording',
            'severity': 'HIGH',
            'title_template': 'Recording Failure',
            'description': 'Video/photo capture failed',
            'confidence': 0.9,
            'explanation': 'The camera had trouble recording video or taking a photo. Some content may be missing or the recording may have stopped.',
            'why_it_matters': 'This is a core function failure. Users buy cameras to record - if this fails, the product is not meeting its basic purpose.',
            'suggested_actions': [
                'Document the recording settings being used (resolution, framerate)',
                'Note the ambient temperature - overheating can cause this',
                'Check if the SD card has enough space and is fast enough',
                'Try to reproduce with different settings'
            ],
            'technical_details': 'Recording failures often relate to SD card write speed limitations, thermal throttling, or video encoder issues.'
        },
        {
            'pattern': r'(disk\s*full|storage\s*full|no\s*space|write\s*failed|sd\s*card\s*error)',
            'category': 'storage',
            'severity': 'HIGH',
            'title_template': 'Storage Error',
            'description': 'Storage-related error occurred',
            'confidence': 0.9,
            'explanation': 'There is a problem with saving files - either the SD card is full, not working properly, or too slow.',
            'why_it_matters': 'Storage issues directly prevent the camera from saving recordings and photos - the main reason people use cameras.',
            'suggested_actions': [
                'Check the SD card storage space remaining',
                'Note the SD card brand, model, and speed class',
                'Try formatting the SD card in the camera',
                'Test with a known-good SD card'
            ],
            'technical_details': 'Storage errors may indicate card degradation, incompatible card speed class, or filesystem corruption.'
        },
        {
            'pattern': r'(lens\s*error|focus\s*failed|aperture\s*stuck|zoom\s*error)',
            'category': 'lens',
            'severity': 'HIGH',
            'title_template': 'Lens/Optical Error',
            'description': 'Camera lens or optical system error',
            'confidence': 0.9,
            'explanation': 'The camera lens is having mechanical issues - it may not focus, zoom, or move correctly.',
            'why_it_matters': 'Lens issues directly affect image quality. Photos and videos may be blurry or improperly framed.',
            'suggested_actions': [
                'Check if the lens is physically obstructed or dirty',
                'Listen for unusual sounds when the lens moves',
                'Test zoom and focus in different lighting conditions',
                'Note if this started after a drop or impact'
            ],
            'technical_details': 'Lens errors often indicate mechanical motor issues, dust contamination, or physical damage to optical components.'
        },

        # Medium severity issues
        {
            'pattern': r'(retry|retrying|attempt\s*\d+|failed,\s*retrying)',
            'category': 'retry',
            'severity': 'MEDIUM',
            'title_template': 'Operation Retry',
            'description': 'Operation required retry attempts',
            'confidence': 0.7,
            'explanation': 'Something did not work on the first try, so the camera automatically tried again. Usually this works out, but frequent retries can slow things down.',
            'why_it_matters': 'Occasional retries are normal, but frequent retries indicate underlying instability that could become worse.',
            'suggested_actions': [
                'Note how often retries are occurring',
                'Check if retries are related to network or storage',
                'Monitor if retry frequency is increasing over time'
            ],
            'technical_details': 'High retry rates may indicate marginal hardware performance or environmental factors affecting operation.'
        },
        {
            'pattern': r'(performance|slow|latency|delay|lag|bottleneck)',
            'category': 'performance',
            'severity': 'MEDIUM',
            'title_template': 'Performance Issue',
            'description': 'Performance degradation detected',
            'confidence': 0.6,
            'explanation': 'The camera is running slower than it should. Operations are taking longer than expected.',
            'why_it_matters': 'Poor performance makes the camera feel unresponsive and can lead to missed moments or user frustration.',
            'suggested_actions': [
                'Note which features feel slow',
                'Check the camera temperature',
                'Test performance after a restart',
                'Compare with expected behavior from product specs'
            ],
            'technical_details': 'Performance issues may result from thermal throttling, memory pressure, or resource-intensive background tasks.'
        },
        {
            'pattern': r'(deprecated|legacy|outdated|obsolete)',
            'category': 'deprecation',
            'severity': 'MEDIUM',
            'title_template': 'Deprecated Feature Usage',
            'description': 'Deprecated functionality in use',
            'confidence': 0.8,
            'explanation': 'The camera is using an old feature or method that may be removed in future updates.',
            'why_it_matters': 'While working now, deprecated features may break after firmware updates, causing unexpected problems.',
            'suggested_actions': [
                'Document which deprecated feature is being used',
                'Report to development team for future removal'
            ],
            'technical_details': 'Deprecated API usage suggests technical debt that should be addressed in future firmware versions.'
        },
        {
            'pattern': r'(battery\s*low|power\s*warning|charging\s*error)',
            'category': 'power',
            'severity': 'MEDIUM',
            'title_template': 'Power Issue',
            'description': 'Battery or power-related issue',
            'confidence': 0.85,
            'explanation': 'The camera is running low on battery or having trouble charging.',
            'why_it_matters': 'Power issues limit how long the camera can be used and may cause unexpected shutdowns.',
            'suggested_actions': [
                'Note the battery percentage when warning appeared',
                'Test how long battery lasts under various conditions',
                'Check if charging works properly',
                'Compare battery life to product specifications'
            ],
            'technical_details': 'Power warnings help prevent data loss from unexpected shutdowns and indicate battery health status.'
        },
        {
            'pattern': r'(temperature|overheating|thermal|too\s*hot|overheat)',
            'category': 'thermal',
            'severity': 'MEDIUM',
            'title_template': 'Thermal Warning',
            'description': 'Temperature-related issue detected',
            'confidence': 0.85,
            'explanation': 'The camera is getting too hot. Like how your phone gets warm when doing too much, cameras can overheat during heavy use.',
            'why_it_matters': 'Overheating can cause reduced performance, recording limits, or automatic shutdown to protect the hardware.',
            'suggested_actions': [
                'Note the ambient temperature during testing',
                'Record what settings/features caused overheating',
                'Check how long until thermal throttling kicks in',
                'Test in cooler environment to compare'
            ],
            'technical_details': 'Thermal issues indicate the camera is operating near its thermal design limits, often during 4K or high framerate recording.'
        },

        # Low severity issues
        {
            'pattern': r'(warning|warn|caution)',
            'category': 'warning',
            'severity': 'LOW',
            'title_template': 'General Warning',
            'description': 'Warning condition detected',
            'confidence': 0.5,
            'explanation': 'The camera noticed something that might need attention, but it is not causing immediate problems.',
            'why_it_matters': 'Warnings are early indicators - addressing them can prevent bigger issues later.',
            'suggested_actions': [
                'Read the specific warning message for details',
                'Note if warnings are recurring',
                'Monitor if warnings lead to errors'
            ],
            'technical_details': 'Generic warnings capture conditions that do not match specific patterns but may indicate emerging issues.'
        },
        {
            'pattern': r'(unexpected|anomaly|unusual|strange)',
            'category': 'anomaly',
            'severity': 'LOW',
            'title_template': 'Unexpected Behavior',
            'description': 'Unusual behavior detected',
            'confidence': 0.5,
            'explanation': 'Something happened that the camera did not expect. It may or may not cause problems.',
            'why_it_matters': 'Anomalies can be early warning signs of developing issues.',
            'suggested_actions': [
                'Document the context around the anomaly',
                'Note if this is a one-time or recurring event',
                'Include in test report for developer review'
            ],
            'technical_details': 'Anomaly detection captures edge cases that may require investigation.'
        },
    ]

    # Stack trace patterns
    STACK_TRACE_PATTERNS = [
        r'(Traceback\s*\(most\s*recent\s*call\s*last\):)',  # Python
        r'(Exception\s+in\s+thread)',  # Java
        r'(at\s+\w+\.\w+\([^)]+:\d+\))',  # Java stack frame
        r'(\#\d+\s+0x[0-9a-fA-F]+)',  # C/C++ stack frame
        r'(Stack\s*trace:)',
        r'(Call\s*stack:)',
    ]

    # Severity explanations for beginners
    SEVERITY_INFO = {
        'CRITICAL': {
            'label': 'Critical',
            'color': 'danger',
            'icon': 'exclamation-octagon-fill',
            'description': 'Severe issue - Camera may stop working or lose data',
            'user_impact': 'High - Users will definitely notice and be affected',
            'priority': 'Fix immediately - This is a blocker'
        },
        'HIGH': {
            'label': 'High',
            'color': 'danger',
            'icon': 'exclamation-triangle-fill',
            'description': 'Significant issue - A main feature is not working',
            'user_impact': 'High - Users cannot complete common tasks',
            'priority': 'Fix soon - Major functionality affected'
        },
        'MEDIUM': {
            'label': 'Medium',
            'color': 'warning',
            'icon': 'exclamation-triangle',
            'description': 'Moderate issue - Something is degraded but still works',
            'user_impact': 'Medium - Users may notice reduced quality or speed',
            'priority': 'Plan to fix - Should be addressed in near term'
        },
        'LOW': {
            'label': 'Low',
            'color': 'info',
            'icon': 'info-circle',
            'description': 'Minor issue - Small glitch or edge case',
            'user_impact': 'Low - Most users will not notice',
            'priority': 'Nice to fix - Address when time permits'
        },
        'INFO': {
            'label': 'Info',
            'color': 'secondary',
            'icon': 'info-circle',
            'description': 'Informational - Not necessarily a problem',
            'user_impact': 'None - For awareness only',
            'priority': 'No action needed - Monitor only'
        }
    }

    # Category explanations
    CATEGORY_INFO = {
        'crash': {
            'name': 'Crashes',
            'icon': 'x-octagon',
            'description': 'Software stopped working unexpectedly'
        },
        'memory': {
            'name': 'Memory Issues',
            'icon': 'memory',
            'description': 'Problems with system memory (RAM)'
        },
        'data_integrity': {
            'name': 'Data Corruption',
            'icon': 'file-earmark-x',
            'description': 'Files or data got damaged'
        },
        'timeout': {
            'name': 'Timeouts',
            'icon': 'clock-history',
            'description': 'Operations took too long'
        },
        'connection': {
            'name': 'Connection Issues',
            'icon': 'wifi-off',
            'description': 'Network or WiFi problems'
        },
        'recording': {
            'name': 'Recording Failures',
            'icon': 'camera-video-off',
            'description': 'Problems capturing video or photos'
        },
        'storage': {
            'name': 'Storage Issues',
            'icon': 'hdd',
            'description': 'SD card or storage problems'
        },
        'lens': {
            'name': 'Lens/Optical',
            'icon': 'aperture',
            'description': 'Camera lens mechanical issues'
        },
        'retry': {
            'name': 'Retry Events',
            'icon': 'arrow-repeat',
            'description': 'Operations needed multiple attempts'
        },
        'performance': {
            'name': 'Performance',
            'icon': 'speedometer',
            'description': 'Slowness or lag issues'
        },
        'deprecation': {
            'name': 'Deprecation',
            'icon': 'calendar-x',
            'description': 'Using outdated features'
        },
        'power': {
            'name': 'Power/Battery',
            'icon': 'battery-half',
            'description': 'Battery or charging issues'
        },
        'thermal': {
            'name': 'Temperature',
            'icon': 'thermometer-half',
            'description': 'Overheating issues'
        },
        'warning': {
            'name': 'Warnings',
            'icon': 'exclamation-triangle',
            'description': 'General warning messages'
        },
        'anomaly': {
            'name': 'Anomalies',
            'icon': 'question-circle',
            'description': 'Unexpected behavior'
        },
        'error': {
            'name': 'General Errors',
            'icon': 'x-circle',
            'description': 'Unclassified error messages'
        },
        'critical': {
            'name': 'Critical Errors',
            'icon': 'x-octagon-fill',
            'description': 'Severe unclassified errors'
        },
        'communication': {
            'name': 'Communication Errors',
            'icon': 'arrow-left-right',
            'description': 'Inter-service communication failures'
        },
        'signal': {
            'name': 'Signal Issues',
            'icon': 'broadcast',
            'description': 'Network/cellular signal problems'
        }
    }

    def __init__(self):
        # Compile patterns for performance
        self.error_regexes = []
        for pattern_info in self.ERROR_PATTERNS:
            compiled = re.compile(pattern_info['pattern'], re.IGNORECASE)
            self.error_regexes.append((compiled, pattern_info))

        self.stack_trace_regexes = [re.compile(p, re.IGNORECASE) for p in self.STACK_TRACE_PATTERNS]

    def detect_issues(self, entries: List[Dict]) -> List[Dict]:
        """
        Analyze log entries and detect issues.
        Returns a list of detected issues with details.
        """
        issues = []
        issue_groups = defaultdict(list)  # Group similar issues

        for entry in entries:
            line_issues = self._detect_line_issues(entry)
            for issue in line_issues:
                # Create a key for grouping similar issues
                group_key = (issue['category'], issue['title'])
                issue_groups[group_key].append({
                    'entry': entry,
                    'issue': issue
                })

        # Consolidate grouped issues
        for (category, title), occurrences in issue_groups.items():
            first_entry = occurrences[0]['entry']
            last_entry = occurrences[-1]['entry']
            issue_info = occurrences[0]['issue']

            # Collect affected line numbers
            affected_lines = [occ['entry']['line_number'] for occ in occurrences]

            # Get context - show more log lines with line numbers
            context_entries = []
            # Show first 5 occurrences with line numbers
            for i, occ in enumerate(occurrences[:5]):
                line_num = occ['entry']['line_number']
                raw = occ['entry']['raw_content']
                service = occ['entry'].get('service', '')
                context_entries.append(f"[Line {line_num}] {raw}")

            if len(occurrences) > 5:
                context_entries.append(f"\n... and {len(occurrences) - 5} more occurrences ...")

            issue = {
                'title': title,
                'description': issue_info['description'],
                'severity': issue_info['severity'],
                'category': category,
                'first_occurrence': first_entry['timestamp'],
                'last_occurrence': last_entry['timestamp'],
                'occurrence_count': len(occurrences),
                'affected_lines': affected_lines,
                'context': '\n'.join(context_entries),
                'confidence_score': issue_info['confidence'],
                'status': 'open',
                # Enhanced fields for user-friendly display
                'explanation': issue_info.get('explanation', ''),
                'why_it_matters': issue_info.get('why_it_matters', ''),
                'suggested_actions': issue_info.get('suggested_actions', []),
                'technical_details': issue_info.get('technical_details', '')
            }
            issues.append(issue)

        # Detect high-frequency repeating issues (same error happening many times)
        for issue in issues:
            if issue['occurrence_count'] >= 10:
                # This is a repeating issue - upgrade severity if it was low/medium
                if issue['severity'] in ['LOW', 'MEDIUM']:
                    issue['severity'] = 'HIGH'
                # Add note about frequency
                issue['description'] = f"{issue['description']} (Occurred {issue['occurrence_count']} times - this is a repeating issue)"
                if 'Check the frequency pattern' not in str(issue.get('suggested_actions', [])):
                    issue['suggested_actions'] = issue.get('suggested_actions', []) + [
                        'This issue is repeating frequently - investigate root cause',
                        f'Occurred {issue["occurrence_count"]} times in this log'
                    ]

        # Sort by severity and occurrence count
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        issues.sort(key=lambda x: (severity_order.get(x['severity'], 5), -x['occurrence_count']))

        return issues

    def _detect_line_issues(self, entry: Dict) -> List[Dict]:
        """Detect issues in a single log entry"""
        issues = []
        line = entry['raw_content']
        severity = entry['severity']

        # Check all lines for known error patterns (not just ERROR/CRITICAL severity)
        # This catches issues even when logged at WARNING or INFO level
        for regex, pattern_info in self.error_regexes:
            if regex.search(line):
                issues.append({
                    'category': pattern_info['category'],
                    'severity': pattern_info['severity'],
                    'title': pattern_info['title_template'],
                    'description': pattern_info['description'],
                    'confidence': pattern_info['confidence'],
                    'explanation': pattern_info.get('explanation', ''),
                    'why_it_matters': pattern_info.get('why_it_matters', ''),
                    'suggested_actions': pattern_info.get('suggested_actions', []),
                    'technical_details': pattern_info.get('technical_details', '')
                })
                break  # Only match first pattern per line

        # If no specific pattern matched, check severity
        if not issues:
            if severity == 'ERROR':
                # Extract meaningful part of message for title
                service = entry.get('service', 'Unknown')
                msg_preview = entry.get('message', line)[:100]
                issues.append({
                    'category': 'error',
                    'severity': 'HIGH',
                    'title': f'Error in {service}' if service else 'Error Detected',
                    'description': msg_preview,
                    'confidence': 0.7,
                    'explanation': 'An error occurred that does not match a known pattern. Review the message for details.',
                    'why_it_matters': 'Errors indicate something went wrong. Even unclassified errors may affect camera functionality.',
                    'suggested_actions': [
                        'Read the error message carefully',
                        'Note what was happening when this error occurred',
                        'Check if this error repeats',
                        'Include in bug report if it affects functionality'
                    ],
                    'technical_details': f'Unclassified error from {service}.'
                })
            elif severity == 'CRITICAL':
                service = entry.get('service', 'Unknown')
                msg_preview = entry.get('message', line)[:100]
                issues.append({
                    'category': 'critical',
                    'severity': 'CRITICAL',
                    'title': f'Critical Error in {service}' if service else 'Critical Error',
                    'description': msg_preview,
                    'confidence': 0.8,
                    'explanation': 'A severe error occurred. This needs immediate attention.',
                    'why_it_matters': 'Critical errors typically mean something important failed or the system is at risk.',
                    'suggested_actions': [
                        'Document exactly what was happening before this error',
                        'Note if the camera recovered or needed restart',
                        'This should be reported as a high-priority bug',
                        'Try to reproduce to confirm it is not a one-time glitch'
                    ],
                    'technical_details': f'Unclassified critical error from {service}.'
                })

        return issues

    def detect_patterns(self, entries: List[Dict]) -> Dict:
        """
        Detect patterns and trends in log data.
        Returns analytics about error frequency, timing, etc.
        """
        patterns = {
            'error_frequency': defaultdict(int),
            'errors_by_service': defaultdict(int),
            'errors_by_hour': defaultdict(int),
            'error_rate_trend': [],
            'service_health': {},
            'common_error_messages': defaultdict(int)
        }

        # Time-based error tracking
        time_buckets = defaultdict(lambda: {'total': 0, 'errors': 0})

        for entry in entries:
            severity = entry['severity']
            service = entry['service'] or 'unknown'
            timestamp = entry['timestamp']

            # Count by severity
            patterns['error_frequency'][severity] += 1

            # Count errors by service
            if severity in ['CRITICAL', 'ERROR']:
                patterns['errors_by_service'][service] += 1

                # Track error messages
                message = entry.get('message', '')[:100]
                if message:
                    patterns['common_error_messages'][message] += 1

            # Time-based analysis
            if timestamp:
                hour = timestamp.hour
                patterns['errors_by_hour'][hour] += 1

                # Create 10-minute buckets for trend analysis
                bucket = timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0, microsecond=0)
                time_buckets[bucket]['total'] += 1
                if severity in ['CRITICAL', 'ERROR']:
                    time_buckets[bucket]['errors'] += 1

        # Calculate error rate trend
        for bucket in sorted(time_buckets.keys()):
            data = time_buckets[bucket]
            rate = (data['errors'] / data['total'] * 100) if data['total'] > 0 else 0
            patterns['error_rate_trend'].append({
                'time': bucket.isoformat() if bucket else None,
                'total': data['total'],
                'errors': data['errors'],
                'rate': round(rate, 2)
            })

        # Calculate service health scores
        total_entries_by_service = defaultdict(int)
        for entry in entries:
            service = entry['service'] or 'unknown'
            total_entries_by_service[service] += 1

        for service, error_count in patterns['errors_by_service'].items():
            total = total_entries_by_service[service]
            error_rate = (error_count / total * 100) if total > 0 else 0
            health_score = max(0, 100 - (error_rate * 5))  # Penalize 5% per error percentage
            patterns['service_health'][service] = {
                'total_entries': total,
                'error_count': error_count,
                'error_rate': round(error_rate, 2),
                'health_score': round(health_score, 1)
            }

        # Convert defaultdicts to regular dicts and get top items
        patterns['error_frequency'] = dict(patterns['error_frequency'])
        patterns['errors_by_service'] = dict(patterns['errors_by_service'])
        patterns['errors_by_hour'] = dict(patterns['errors_by_hour'])

        # Get top 10 common error messages
        top_messages = sorted(patterns['common_error_messages'].items(), key=lambda x: -x[1])[:10]
        patterns['common_error_messages'] = [{'message': m, 'count': c} for m, c in top_messages]

        return patterns

    def get_health_score(self, entries: List[Dict], issues: List[Dict]) -> Dict:
        """
        Calculate an overall health score for the log file.
        Returns a beginner-friendly health assessment.
        """
        total_entries = len(entries)
        if total_entries == 0:
            return {
                'score': 100,
                'status': 'unknown',
                'label': 'No Data',
                'color': 'secondary',
                'description': 'No log entries to analyze',
                'icon': 'question-circle'
            }

        # Count issues by severity
        critical_count = sum(1 for i in issues if i.get('severity') == 'CRITICAL')
        high_count = sum(1 for i in issues if i.get('severity') == 'HIGH')
        medium_count = sum(1 for i in issues if i.get('severity') == 'MEDIUM')
        low_count = sum(1 for i in issues if i.get('severity') == 'LOW')

        # Count errors in entries
        error_entries = sum(1 for e in entries if e.get('severity') in ['CRITICAL', 'ERROR'])
        error_rate = (error_entries / total_entries) * 100

        # Calculate health score (100 = perfect, 0 = critical issues)
        score = 100
        score -= critical_count * 25  # Critical issues heavily penalize
        score -= high_count * 10  # High issues moderately penalize
        score -= medium_count * 3  # Medium issues slightly penalize
        score -= low_count * 1  # Low issues minimally penalize
        score -= error_rate * 0.5  # Error rate impact

        score = max(0, min(100, score))  # Clamp to 0-100

        # Determine status and label
        if score >= 90:
            status = 'good'
            label = 'Good'
            color = 'success'
            icon = 'check-circle-fill'
            description = 'Log looks healthy with minimal issues.'
        elif score >= 70:
            status = 'fair'
            label = 'Fair'
            color = 'info'
            icon = 'info-circle-fill'
            description = 'Some issues detected but nothing critical.'
        elif score >= 50:
            status = 'warning'
            label = 'Warning'
            color = 'warning'
            icon = 'exclamation-triangle-fill'
            description = 'Multiple issues found that need attention.'
        else:
            status = 'critical'
            label = 'Critical'
            color = 'danger'
            icon = 'exclamation-octagon-fill'
            description = 'Serious issues detected. Immediate review recommended.'

        return {
            'score': round(score),
            'status': status,
            'label': label,
            'color': color,
            'description': description,
            'icon': icon,
            'breakdown': {
                'critical_issues': critical_count,
                'high_issues': high_count,
                'medium_issues': medium_count,
                'low_issues': low_count,
                'error_rate': round(error_rate, 1)
            }
        }

    def get_severity_info(self, severity: str) -> Dict:
        """Get user-friendly information about a severity level"""
        return self.SEVERITY_INFO.get(severity, self.SEVERITY_INFO['INFO'])

    def get_category_info(self, category: str) -> Dict:
        """Get user-friendly information about an issue category"""
        return self.CATEGORY_INFO.get(category, {
            'name': category.replace('_', ' ').title(),
            'icon': 'circle',
            'description': 'Issue category'
        })

    def get_all_category_info(self) -> Dict:
        """Get all category information"""
        return self.CATEGORY_INFO

    def get_all_severity_info(self) -> Dict:
        """Get all severity information"""
        return self.SEVERITY_INFO

    def is_stack_trace(self, line: str) -> bool:
        """Check if a line appears to be part of a stack trace"""
        for regex in self.stack_trace_regexes:
            if regex.search(line):
                return True
        return False

    def get_context_lines(self, entries: List[Dict], line_number: int, before: int = 5, after: int = 5) -> List[Dict]:
        """Get surrounding context for a specific line"""
        context = []
        for entry in entries:
            if line_number - before <= entry['line_number'] <= line_number + after:
                context.append(entry)
        return context

    def detect_error_sequences(self, entries: List[Dict], window_minutes: int = 5) -> List[Dict]:
        """
        Detect sequences of related errors that occur close together.
        Helps identify cascading failures.
        """
        sequences = []
        current_sequence = []
        last_error_time = None

        for entry in entries:
            if entry.get('severity') in ['CRITICAL', 'ERROR']:
                timestamp = entry.get('timestamp')
                if timestamp:
                    if last_error_time:
                        time_diff = (timestamp - last_error_time).total_seconds() / 60
                        if time_diff <= window_minutes:
                            current_sequence.append(entry)
                        else:
                            if len(current_sequence) >= 2:
                                sequences.append({
                                    'entries': current_sequence.copy(),
                                    'count': len(current_sequence),
                                    'start_time': current_sequence[0]['timestamp'],
                                    'end_time': current_sequence[-1]['timestamp'],
                                    'services': list(set(e.get('service') for e in current_sequence if e.get('service')))
                                })
                            current_sequence = [entry]
                    else:
                        current_sequence = [entry]
                    last_error_time = timestamp

        # Don't forget the last sequence
        if len(current_sequence) >= 2:
            sequences.append({
                'entries': current_sequence.copy(),
                'count': len(current_sequence),
                'start_time': current_sequence[0]['timestamp'],
                'end_time': current_sequence[-1]['timestamp'],
                'services': list(set(e.get('service') for e in current_sequence if e.get('service')))
            })

        return sequences
