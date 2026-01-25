"""
Intelligent Log Search Service
AI-like natural language understanding for log analysis queries
"""
import re


class IntelligentSearch:
    """
    Understands natural language queries and finds relevant log sections.

    Examples:
    - "camera is not recording" -> searches for recording issues
    - "upload failing to cloud" -> searches for cloud/upload errors
    - "show me the reboot flow" -> shows boot sequence
    - "why is GPS not working" -> searches for GPS issues
    """

    # Query patterns mapped to search strategies
    QUERY_PATTERNS = {
        # Recording issues
        'recording': {
            'keywords': ['record', 'recording', 'video', 'capture', 'save', 'saving'],
            'patterns': [r'record', r'video', r'capture', r'mp4', r'h264', r'h265', r'encoder', r'stream'],
            'related_services': ['video', 'recorder', 'encoder', 'stream', 'storage'],
            'description': 'Video recording and capture'
        },

        # Upload/Cloud issues
        'cloud_upload': {
            'keywords': ['upload', 'cloud', 'sync', 'transfer', 'server', 'network', 'send', 'sending'],
            'patterns': [r'upload', r'cloud', r'sync', r'transfer', r'http', r'https', r'server', r'post', r'put'],
            'related_services': ['upload', 'cloud', 'sync', 'http', 'network', 'wifi'],
            'description': 'Cloud upload and data sync'
        },

        # Boot/Reboot flow
        'boot': {
            'keywords': ['boot', 'reboot', 'startup', 'start', 'starting', 'init', 'initialize', 'power on'],
            'patterns': [r'boot', r'reboot', r'startup', r'init', r'starting', r'loaded', r'ready'],
            'related_services': ['system', 'init', 'kernel', 'boot'],
            'flow_markers': {
                'start': [r'system.*start', r'boot.*start', r'kernel.*boot', r'init\['],
                'end': [r'system.*ready', r'boot.*complete', r'all.*services.*started']
            },
            'description': 'System boot and startup sequence'
        },

        # Shutdown flow
        'shutdown': {
            'keywords': ['shutdown', 'shut down', 'power off', 'poweroff', 'stop', 'stopping', 'halt'],
            'patterns': [r'shutdown', r'stopping', r'stop', r'halt', r'power.*off', r'terminating'],
            'related_services': ['system', 'power', 'shutdown'],
            'flow_markers': {
                'start': [r'shutdown.*init', r'stopping.*service', r'power.*off.*request'],
                'end': [r'system.*halt', r'power.*off', r'goodbye']
            },
            'description': 'System shutdown sequence'
        },

        # OTA/Update flow
        'ota': {
            'keywords': ['ota', 'update', 'upgrade', 'firmware', 'flash', 'version'],
            'patterns': [r'ota', r'update', r'upgrade', r'firmware', r'flash', r'version', r'download.*update'],
            'related_services': ['ota', 'update', 'upgrade', 'firmware'],
            'flow_markers': {
                'start': [r'ota.*start', r'update.*check', r'firmware.*download'],
                'end': [r'ota.*complete', r'update.*success', r'firmware.*applied', r'reboot.*update']
            },
            'description': 'OTA firmware update process'
        },

        # WiFi/Network issues
        'wifi': {
            'keywords': ['wifi', 'wi-fi', 'wireless', 'network', 'connection', 'connect', 'disconnect', 'ssid'],
            'patterns': [r'wifi', r'wlan', r'wireless', r'network', r'connect', r'disconnect', r'ssid', r'signal'],
            'related_services': ['wifi', 'wlan', 'network', 'wpa'],
            'description': 'WiFi and network connectivity'
        },

        # GPS issues
        'gps': {
            'keywords': ['gps', 'location', 'position', 'satellite', 'gnss', 'coordinates', 'lat', 'lon'],
            'patterns': [r'gps', r'gnss', r'location', r'position', r'satellite', r'fix', r'nmea'],
            'related_services': ['gps', 'gnss', 'location'],
            'description': 'GPS and location services'
        },

        # Storage/SD card issues
        'storage': {
            'keywords': ['storage', 'sd', 'card', 'disk', 'space', 'memory', 'full', 'write', 'read'],
            'patterns': [r'storage', r'sd.*card', r'mmc', r'disk', r'space', r'mount', r'write', r'read'],
            'related_services': ['storage', 'mmc', 'sdcard', 'disk'],
            'description': 'Storage and SD card operations'
        },

        # Camera/Sensor issues
        'camera': {
            'keywords': ['camera', 'sensor', 'lens', 'isp', 'image', 'picture', 'photo', 'preview'],
            'patterns': [r'camera', r'sensor', r'isp', r'image', r'preview', r'capture', r'frame'],
            'related_services': ['camera', 'sensor', 'isp', 'video'],
            'description': 'Camera and image sensor'
        },

        # Crash/Error issues
        'crash': {
            'keywords': ['crash', 'error', 'fail', 'failed', 'bug', 'problem', 'issue', 'broken', 'not working'],
            'patterns': [r'crash', r'error', r'fail', r'exception', r'segfault', r'panic', r'fatal'],
            'related_services': ['system', 'kernel'],
            'description': 'System crashes and errors'
        },

        # Memory issues
        'memory': {
            'keywords': ['memory', 'ram', 'oom', 'leak', 'allocation', 'malloc', 'free'],
            'patterns': [r'memory', r'oom', r'out.*of.*memory', r'malloc', r'alloc', r'free', r'heap'],
            'related_services': ['system', 'kernel', 'memory'],
            'description': 'Memory usage and allocation'
        },

        # Temperature issues
        'temperature': {
            'keywords': ['temperature', 'temp', 'heat', 'hot', 'thermal', 'overheat', 'cooling'],
            'patterns': [r'temp', r'thermal', r'heat', r'overheat', r'celsius', r'degree'],
            'related_services': ['thermal', 'system', 'sensor'],
            'description': 'Temperature and thermal management'
        },

        # Audio issues
        'audio': {
            'keywords': ['audio', 'sound', 'speaker', 'microphone', 'mic', 'voice', 'volume'],
            'patterns': [r'audio', r'sound', r'speaker', r'mic', r'voice', r'alsa', r'pcm'],
            'related_services': ['audio', 'sound', 'alsa'],
            'description': 'Audio and sound system'
        },

        # Bluetooth issues
        'bluetooth': {
            'keywords': ['bluetooth', 'bt', 'pair', 'pairing', 'ble'],
            'patterns': [r'bluetooth', r'bt[^a-z]', r'ble', r'pair', r'hci'],
            'related_services': ['bluetooth', 'bt', 'hci'],
            'description': 'Bluetooth connectivity'
        },

        # Power/Battery issues
        'power': {
            'keywords': ['power', 'battery', 'charge', 'charging', 'voltage', 'current', 'acc', 'ignition'],
            'patterns': [r'power', r'battery', r'charge', r'voltage', r'current', r'pmic', r'acc', r'ignition'],
            'related_services': ['power', 'battery', 'pmic', 'charger'],
            'description': 'Power and battery management'
        },

        # Performance/System issues
        'performance': {
            'keywords': ['slow', 'performance', 'lag', 'laggy', 'freeze', 'frozen', 'hang', 'hanging', 'stuck', 'unresponsive', 'cpu', 'load', 'timeout', 'timed out', 'watchdog', 'deadlock'],
            'patterns': [r'slow', r'performance', r'cpu', r'load', r'freeze', r'hung', r'stuck', r'latency', r'delay', r'timeout', r'timed.*out', r'watchdog'],
            'related_services': ['system', 'kernel', 'cpu', 'watchdog'],
            'description': 'System performance and responsiveness'
        },

        # Internet/Cellular/LTE issues
        'cellular': {
            'keywords': ['lte', 'cellular', 'mobile', '4g', '5g', 'modem', 'sim', 'carrier', 'signal', 'internet', 'data'],
            'patterns': [r'lte', r'cellular', r'modem', r'sim', r'carrier', r'4g', r'5g', r'mobile.*data', r'apn'],
            'related_services': ['modem', 'cellular', 'lte', 'network'],
            'description': 'Cellular/LTE mobile data connection'
        },

        # USB issues
        'usb': {
            'keywords': ['usb', 'gadget', 'otg', 'mass storage', 'adb', 'fastboot'],
            'patterns': [r'usb', r'gadget', r'otg', r'adb', r'fastboot', r'mass.*storage'],
            'related_services': ['usb', 'gadget', 'adb'],
            'description': 'USB connectivity and devices'
        },

        # Display/HDMI issues
        'display': {
            'keywords': ['display', 'screen', 'hdmi', 'lcd', 'oled', 'framebuffer', 'resolution', 'video out'],
            'patterns': [r'display', r'hdmi', r'lcd', r'screen', r'framebuffer', r'fb[0-9]', r'drm', r'resolution'],
            'related_services': ['display', 'hdmi', 'drm', 'fb'],
            'description': 'Display and video output'
        },

        # Firmware/Version issues
        'firmware': {
            'keywords': ['firmware', 'version', 'build', 'release', 'software'],
            'patterns': [r'firmware', r'version', r'build', r'release', r'software.*version'],
            'related_services': ['firmware', 'ota', 'update'],
            'description': 'Firmware and software version'
        }
    }

    # Typo corrections - map common typos to correct keywords
    TYPO_CORRECTIONS = {
        'recoring': 'recording',
        'recored': 'record',
        'camra': 'camera',
        'cammera': 'camera',
        'camrea': 'camera',
        'wfi': 'wifi',
        'wify': 'wifi',
        'wirless': 'wireless',
        'wireles': 'wireless',
        'gsp': 'gps',
        'bluetoth': 'bluetooth',
        'bluetooh': 'bluetooth',
        'stoarge': 'storage',
        'storge': 'storage',
        'memeory': 'memory',
        'memroy': 'memory',
        'uplaod': 'upload',
        'uplod': 'upload',
        'donwload': 'download',
        'donload': 'download',
        'conection': 'connection',
        'conectivity': 'connectivity',
        'temperture': 'temperature',
        'temprature': 'temperature',
        'bootup': 'boot',
        'rebot': 'reboot',
        'shtudown': 'shutdown',
        'shutdwon': 'shutdown',
        'erros': 'errors',
        'eror': 'error',
        'satelite': 'satellite',
        'sattelite': 'satellite',
    }

    # Common question patterns
    QUESTION_PATTERNS = [
        (r'why.*(not|isn\'t|doesn\'t|won\'t|can\'t)', 'problem'),  # "why is X not working"
        (r'(can you|could you|please).*help', 'problem'),  # "can you help me"
        (r'i (see|have|notice|found|got).*(error|issue|problem|leak|fail)', 'problem'),  # "I see/have an error"
        (r'(not|isn\'t|doesn\'t|won\'t) work', 'problem'),  # "X not working"
        (r'(problem|issue|error|bug) with', 'problem'),  # "problem with X"
        (r'(failing|failed|broken|stuck)', 'problem'),  # "X is failing"
        (r'show.*flow', 'flow'),  # "show me the boot flow"
        (r'what.*happen', 'investigation'),  # "what happened with X"
        (r'find.*error|find.*issue|find.*problem', 'errors'),  # "find errors in X"
        (r'check.*(status|error|issue|log)', 'investigation'),  # "check the status"
        (r'is.*working', 'status'),  # "is GPS working"
        (r'when.*did|when.*was', 'timeline'),  # "when did X happen"
        (r'how.*many|count', 'count'),  # "how many errors"
        (r'(debug|diagnose|troubleshoot|investigate)', 'problem'),  # "debug this"
    ]

    def __init__(self):
        self.last_context = None

    def search(self, query, entries, sections=None):
        """
        Process a natural language query and return relevant results.

        Args:
            query: Natural language query from user
            entries: List of log entries
            sections: Optional list of detected sections

        Returns:
            dict with search results, explanation, and suggestions
        """
        query_lower = query.lower().strip()

        # Detect what the user is asking about
        detected_topics = self._detect_topics(query_lower)
        question_type = self._detect_question_type(query_lower)

        if not detected_topics:
            # Try to find any relevant keywords
            detected_topics = self._fuzzy_topic_match(query_lower)

        if not detected_topics:
            return {
                'success': False,
                'message': "I couldn't understand what you're looking for. Try asking about specific topics like recording, upload, GPS, WiFi, boot, shutdown, etc.",
                'suggestions': [
                    "Why is the camera not recording?",
                    "Show me the boot flow",
                    "Find upload errors",
                    "What happened with GPS?"
                ]
            }

        # Build search patterns from detected topics
        search_patterns = []
        related_services = set()
        topic_descriptions = []

        for topic in detected_topics:
            topic_info = self.QUERY_PATTERNS[topic]
            search_patterns.extend(topic_info['patterns'])
            related_services.update(topic_info['related_services'])
            topic_descriptions.append(topic_info['description'])

        # Search entries
        results = self._search_entries(entries, search_patterns, related_services, question_type)

        # If looking for a flow, try to find the flow sequence
        flow_result = None
        if question_type == 'flow' or 'flow' in query_lower:
            for topic in detected_topics:
                if 'flow_markers' in self.QUERY_PATTERNS[topic]:
                    flow_result = self._find_flow(entries, self.QUERY_PATTERNS[topic]['flow_markers'])
                    if flow_result:
                        break

        # Build response
        response = {
            'success': True,
            'query': query,
            'detected_topics': detected_topics,
            'topic_descriptions': topic_descriptions,
            'question_type': question_type,
            'total_matches': len(results['matches']),
            'entries': results['matches'][:50],  # Limit to 50 entries
            'errors_found': results['errors'],
            'warnings_found': results['warnings'],
            'services_involved': list(results['services']),
            'flow': flow_result,
            'analysis': self._generate_analysis(results, detected_topics, question_type),
            'follow_up_questions': self._generate_follow_ups(detected_topics, results)
        }

        self.last_context = response
        return response

    def _correct_typos(self, query):
        """Correct common typos in the query."""
        words = query.split()
        corrected_words = []
        for word in words:
            # Check if word is a known typo
            corrected = self.TYPO_CORRECTIONS.get(word.lower(), word)
            corrected_words.append(corrected)
        return ' '.join(corrected_words)

    def _detect_topics(self, query):
        """Detect which topics the query is about."""
        # First correct typos
        query = self._correct_typos(query)
        detected = []

        for topic, info in self.QUERY_PATTERNS.items():
            for keyword in info['keywords']:
                if keyword in query:
                    if topic not in detected:
                        detected.append(topic)
                    break

        return detected

    def _fuzzy_topic_match(self, query):
        """Try to match query to topics even with typos or variations."""
        # First correct typos
        query = self._correct_typos(query)
        words = query.split()
        detected = []

        for word in words:
            if len(word) < 3:
                continue
            for topic, info in self.QUERY_PATTERNS.items():
                for keyword in info['keywords']:
                    # Check if word is similar (contains or is contained)
                    if word in keyword or keyword in word:
                        if topic not in detected:
                            detected.append(topic)
                        break

        return detected

    def _detect_question_type(self, query):
        """Detect what type of question is being asked."""
        for pattern, qtype in self.QUESTION_PATTERNS:
            if re.search(pattern, query):
                return qtype
        return 'general'

    def _search_entries(self, entries, patterns, services, question_type):
        """Search entries using patterns and services."""
        matches = []
        errors = []
        warnings = []
        found_services = set()

        combined_pattern = '|'.join(patterns)
        regex = re.compile(combined_pattern, re.IGNORECASE)

        for entry in entries:
            content = entry.get('raw_content', '') or entry.get('message', '') or ''
            service = (entry.get('service', '') or '').lower()
            severity = entry.get('severity', '')

            # Check if entry matches patterns or services
            pattern_match = regex.search(content)
            service_match = any(s in service for s in services)

            if pattern_match or service_match:
                matches.append(entry)
                if service:
                    found_services.add(entry.get('service', ''))

                if severity in ['ERROR', 'CRITICAL']:
                    errors.append(entry)
                elif severity == 'WARNING':
                    warnings.append(entry)

        # If looking for problems/errors, prioritize error entries
        if question_type in ['problem', 'errors']:
            # Put errors first
            matches = errors + [m for m in matches if m not in errors]

        return {
            'matches': matches,
            'errors': errors,
            'warnings': warnings,
            'services': found_services
        }

    def _find_flow(self, entries, flow_markers):
        """Find a specific flow sequence in the log."""
        start_patterns = flow_markers.get('start', [])
        end_patterns = flow_markers.get('end', [])

        flow_entries = []
        in_flow = False
        flow_start_line = None
        flow_end_line = None

        start_regex = re.compile('|'.join(start_patterns), re.IGNORECASE) if start_patterns else None
        end_regex = re.compile('|'.join(end_patterns), re.IGNORECASE) if end_patterns else None

        for entry in entries:
            content = entry.get('raw_content', '') or entry.get('message', '') or ''

            if not in_flow and start_regex and start_regex.search(content):
                in_flow = True
                flow_start_line = entry.get('line_number')

            if in_flow:
                flow_entries.append(entry)

                if end_regex and end_regex.search(content):
                    flow_end_line = entry.get('line_number')
                    break

        if flow_entries:
            return {
                'found': True,
                'start_line': flow_start_line,
                'end_line': flow_end_line or flow_entries[-1].get('line_number'),
                'entry_count': len(flow_entries),
                'entries': flow_entries[:30]  # Limit to 30 entries
            }

        return None

    # Troubleshooting tips for each topic
    TROUBLESHOOTING_TIPS = {
        'memory': [
            "Check which process is consuming most memory",
            "Look for memory allocation failures (malloc, alloc)",
            "Check if OOM killer was triggered",
            "Monitor memory usage over time to identify leaks"
        ],
        'recording': [
            "Verify storage has enough space",
            "Check if encoder is initialized properly",
            "Look for frame drop or buffer overflow errors",
            "Verify camera sensor is working"
        ],
        'cloud_upload': [
            "Check network connectivity (WiFi/LTE)",
            "Verify server is reachable",
            "Look for authentication or timeout errors",
            "Check if files are queued for upload"
        ],
        'wifi': [
            "Check signal strength (RSSI values)",
            "Look for authentication failures",
            "Verify SSID and password are correct",
            "Check for IP address assignment (DHCP)"
        ],
        'gps': [
            "Check if device has clear sky view",
            "Look for antenna connection issues",
            "Verify GPS module is powered on",
            "Check satellite count and signal strength"
        ],
        'storage': [
            "Check available disk space",
            "Look for read/write errors",
            "Verify SD card is properly mounted",
            "Check for file system corruption"
        ],
        'camera': [
            "Verify camera sensor initialization",
            "Check ISP (Image Signal Processor) status",
            "Look for frame capture errors",
            "Check camera driver loading"
        ],
        'crash': [
            "Look for segfault or panic messages",
            "Check which process crashed",
            "Look for stack traces or core dumps",
            "Check for null pointer or buffer overflow"
        ],
        'temperature': [
            "Check temperature readings before shutdown",
            "Look for thermal throttling events",
            "Verify cooling system is working",
            "Check if device is in direct sunlight"
        ],
        'power': [
            "Check battery level before issue",
            "Look for voltage fluctuations",
            "Verify power supply stability",
            "Check ACC/ignition signals"
        ],
        'performance': [
            "Check CPU load at time of issue",
            "Look for processes consuming resources",
            "Check for I/O blocking or deadlocks",
            "Monitor memory usage trends"
        ],
        'cellular': [
            "Check modem initialization",
            "Verify SIM card is detected",
            "Look for network registration status",
            "Check signal strength (RSSI/RSRP)"
        ],
        'boot': [
            "Check boot time duration",
            "Look for services that failed to start",
            "Verify all drivers loaded correctly",
            "Check for dependency issues"
        ],
        'ota': [
            "Check download completion status",
            "Verify firmware signature/checksum",
            "Look for storage space issues",
            "Check if update was interrupted"
        ]
    }

    def _generate_analysis(self, results, topics, question_type):
        """Generate a human-readable, helpful analysis of the search results."""
        total = len(results['matches'])
        errors = len(results['errors'])
        warnings = len(results['warnings'])

        if total == 0:
            return f"I searched for entries related to {', '.join(topics)} but didn't find any matches. This could mean the feature wasn't active during this log period, or the issue might be in a different component."

        analysis_parts = []

        # Friendly intro based on question type
        if question_type == 'problem':
            analysis_parts.append(f"I found {total} relevant log entries that might help explain the issue.")
        else:
            analysis_parts.append(f"I found {total} log entries related to {', '.join(topics)}.")

        # Error analysis with helpful context
        if errors > 0:
            if errors > 10:
                analysis_parts.append(f"**{errors} errors detected** - this is significant and likely indicates a real problem.")
            else:
                analysis_parts.append(f"**{errors} errors detected** - review these for potential root causes.")

        if warnings > 0:
            analysis_parts.append(f"{warnings} warnings found that may provide additional context.")

        # Services involved
        if results['services']:
            services_str = ', '.join(list(results['services'])[:5])
            analysis_parts.append(f"Key services involved: {services_str}")

        # Add topic-specific troubleshooting tips
        tips = []
        for topic in topics:
            if topic in self.TROUBLESHOOTING_TIPS:
                tips.extend(self.TROUBLESHOOTING_TIPS[topic][:2])

        if tips and errors > 0:
            analysis_parts.append(f"\n\n**Troubleshooting tips:** {tips[0]}. {tips[1] if len(tips) > 1 else ''}")

        # Problem-specific conclusion
        if question_type == 'problem':
            if errors > 0:
                analysis_parts.append("\n\nThe errors highlighted in red below are the most likely cause of the issue. Click on line numbers to see the full context in the Raw Log.")
            else:
                analysis_parts.append("\n\nNo errors found in this area - the issue might be configuration-related or caused by a different component.")

        return ' '.join(analysis_parts)

    def _generate_follow_ups(self, topics, results):
        """Generate relevant follow-up questions based on findings."""
        follow_ups = []
        errors = len(results['errors'])

        # Error-based follow-ups
        if errors > 0:
            follow_ups.append("Show me the first error in detail")
            follow_ups.append("What happened before the errors?")

        # Topic-specific follow-ups
        topic_follow_ups = {
            'recording': ["Is storage full?", "Check encoder errors", "Show video stream status"],
            'cloud_upload': ["Is WiFi connected?", "Check server response codes", "Show upload queue"],
            'wifi': ["Show connection history", "Check signal strength", "Find authentication errors"],
            'gps': ["How many satellites?", "Show GPS fix history", "Check antenna status"],
            'storage': ["Check disk space", "Find write errors", "Show mount status"],
            'camera': ["Check sensor init", "Show frame rate", "Find ISP errors"],
            'memory': ["Show memory usage trend", "Find OOM events", "Which process uses most RAM?"],
            'crash': ["Show stack trace", "What process crashed?", "Find core dumps"],
            'temperature': ["Show temp readings", "Find throttling events", "Check fan status"],
            'power': ["Show battery history", "Find voltage drops", "Check charging status"],
            'boot': ["How long was boot?", "Which services failed?", "Show boot timeline"],
            'shutdown': ["Was shutdown clean?", "What triggered shutdown?", "Show last activities"],
            'ota': ["Did download complete?", "Check update status", "Show version info"],
            'performance': ["Show CPU usage", "Find slow operations", "Check for deadlocks"],
            'cellular': ["Is modem connected?", "Check signal strength", "Show SIM status"],
        }

        for topic in topics:
            if topic in topic_follow_ups:
                follow_ups.extend(topic_follow_ups[topic][:2])

        # Remove duplicates while preserving order
        seen = set()
        unique_follow_ups = []
        for q in follow_ups:
            if q not in seen:
                seen.add(q)
                unique_follow_ups.append(q)

        return unique_follow_ups[:5]  # Limit to 5 suggestions
