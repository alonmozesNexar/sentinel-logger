"""
Section Analyzer Service
Breaks log files into logical sections/phases based on what's happening
"""
import re


class SectionAnalyzer:
    """Analyzes log files and breaks them into logical sections/phases"""

    # Section markers - patterns that indicate start of a new section/phase
    SECTION_MARKERS = {
        'boot': {
            'name': 'Boot Sequence',
            'start_patterns': [r'kernel.*boot', r'systemd.*start', r'init\[', r'booting', r'power.?on'],
            'icon': 'bi-power',
            'color': 'success'
        },
        'ota': {
            'name': 'OTA / Firmware Update',
            'start_patterns': [r'ota.*start', r'upgrade.*start', r'firmware.*update', r'checking.*update', r'download.*firmware'],
            'icon': 'bi-cloud-download',
            'color': 'primary'
        },
        'recording': {
            'name': 'Recording Session',
            'start_patterns': [r'recording.*start', r'start.*recording', r'video.*start', r'capture.*begin'],
            'icon': 'bi-record-circle',
            'color': 'danger'
        },
        'shutdown': {
            'name': 'Shutdown Sequence',
            'start_patterns': [r'shutdown', r'shutting.*down', r'power.*off', r'halt', r'reboot'],
            'icon': 'bi-power',
            'color': 'secondary'
        },
        'wifi_connect': {
            'name': 'WiFi Connection',
            'start_patterns': [r'wifi.*connect', r'wlan.*associat', r'network.*connect', r'starting.*wifi'],
            'icon': 'bi-wifi',
            'color': 'info'
        },
        'collision': {
            'name': 'Collision Event',
            'start_patterns': [r'collision.*detect', r'impact.*detect', r'g.?sensor.*trigger', r'emergency.*event'],
            'icon': 'bi-exclamation-triangle',
            'color': 'warning'
        },
        'upload': {
            'name': 'Cloud Upload',
            'start_patterns': [r'upload.*start', r'sync.*start', r'sending.*cloud', r'transfer.*begin'],
            'icon': 'bi-cloud-upload',
            'color': 'info'
        },
        'storage': {
            'name': 'Storage Operation',
            'start_patterns': [r'mount.*sd', r'sd.*card.*detect', r'storage.*init', r'format.*start'],
            'icon': 'bi-sd-card',
            'color': 'warning'
        },
        'camera_init': {
            'name': 'Camera Initialization',
            'start_patterns': [r'camera.*init', r'sensor.*init', r'isp.*start', r'video.*init'],
            'icon': 'bi-camera-video',
            'color': 'primary'
        },
        'gps': {
            'name': 'GPS Acquisition',
            'start_patterns': [r'gps.*start', r'gnss.*init', r'gps.*search', r'acquiring.*satellite'],
            'icon': 'bi-geo-alt',
            'color': 'success'
        }
    }

    def analyze_sections(self, entries):
        """
        Analyze log entries and break into sections

        Returns list of sections with their entries
        """
        if not entries:
            return []

        sections = []
        current_section = None
        section_entries = []

        for i, entry in enumerate(entries):
            content = (entry.get('raw_content', '') or entry.get('message', '') or '').lower()
            line_num = entry.get('line_number', i)

            # Check if this entry marks start of a new section
            new_section_type = self._detect_section_start(content)

            if new_section_type and new_section_type != current_section:
                # Save previous section if exists
                if current_section and section_entries:
                    sections.append(self._create_section(current_section, section_entries))

                # Start new section
                current_section = new_section_type
                section_entries = [entry]
            else:
                # Add to current section
                section_entries.append(entry)

        # Don't forget the last section
        if current_section and section_entries:
            sections.append(self._create_section(current_section, section_entries))

        # If no sections detected, create one "General" section
        if not sections and entries:
            sections.append({
                'id': 'general',
                'name': 'Log Content',
                'icon': 'bi-file-text',
                'color': 'secondary',
                'start_line': entries[0].get('line_number', 1),
                'end_line': entries[-1].get('line_number', len(entries)),
                'entry_count': len(entries),
                'services': self._get_unique_services(entries),
                'components': self._get_unique_components(entries),
                'errors': sum(1 for e in entries if e.get('severity') in ['ERROR', 'CRITICAL']),
                'warnings': sum(1 for e in entries if e.get('severity') == 'WARNING'),
                'entries': entries[:100]  # First 100 entries
            })

        return sections

    def _detect_section_start(self, content):
        """Detect if content marks the start of a new section"""
        for section_id, config in self.SECTION_MARKERS.items():
            for pattern in config['start_patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    return section_id
        return None

    def _create_section(self, section_type, entries):
        """Create a section object from entries"""
        config = self.SECTION_MARKERS.get(section_type, {
            'name': section_type.replace('_', ' ').title(),
            'icon': 'bi-folder',
            'color': 'secondary'
        })

        return {
            'id': section_type,
            'name': config['name'],
            'icon': config['icon'],
            'color': config['color'],
            'start_line': entries[0].get('line_number', 0),
            'end_line': entries[-1].get('line_number', 0),
            'entry_count': len(entries),
            'services': self._get_unique_services(entries),
            'components': self._get_unique_components(entries),
            'errors': sum(1 for e in entries if e.get('severity') in ['ERROR', 'CRITICAL']),
            'warnings': sum(1 for e in entries if e.get('severity') == 'WARNING'),
            'entries': entries[:100]  # Limit to first 100 entries for display
        }

    def _get_unique_services(self, entries):
        """Get unique services from entries"""
        services = set()
        for e in entries:
            if e.get('service'):
                services.add(e['service'])
        return sorted(list(services))

    def _get_unique_components(self, entries):
        """Get unique components from entries"""
        components = set()
        for e in entries:
            if e.get('component'):
                components.add(e['component'])
        return sorted(list(components))

    def get_section_summary(self, entries):
        """Get summary with all sections"""
        sections = self.analyze_sections(entries)

        total_errors = sum(s['errors'] for s in sections)
        total_warnings = sum(s['warnings'] for s in sections)

        return {
            'sections': sections,
            'total_sections': len(sections),
            'total_errors': total_errors,
            'total_warnings': total_warnings
        }
