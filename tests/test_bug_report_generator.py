"""
Comprehensive tests for BugReportGenerator service.
Tests cover:
- All template formats (Default, Jira, GitHub, Minimal)
- All export formats (JSON, Markdown, Plain Text)
- Auto-population of fields
- Edge cases (missing data, special characters, Unicode)
"""
import pytest
import json
from datetime import datetime
from app.services.bug_report_generator import BugReportGenerator


class TestBugReportGeneratorTemplates:
    """Test cases for all template formats."""

    @pytest.fixture
    def generator(self):
        """Create a BugReportGenerator instance."""
        return BugReportGenerator()

    @pytest.fixture
    def standard_issue(self):
        """Create a standard issue with all fields populated."""
        return {
            'title': 'Memory Leak in Video Service',
            'description': 'Memory usage grows continuously during video streaming',
            'severity': 'HIGH',
            'category': 'memory',
            'first_occurrence': datetime(2024, 1, 15, 10, 30, 0),
            'last_occurrence': datetime(2024, 1, 15, 14, 45, 30),
            'occurrence_count': 47,
            'affected_lines': [100, 101, 102, 103, 104],
            'context': '2024-01-15 10:30:00 ERROR [video-service] Memory allocation failed\n2024-01-15 10:30:01 ERROR [video-service] OOM killer invoked',
            'confidence_score': 0.95,
        }

    @pytest.fixture
    def standard_device_info(self):
        """Create standard device information."""
        return {
            'model': 'Camera-X100',
            'firmware_version': '2.1.4',
            'serial_number': 'CAM-2024-001234',
        }

    # ==================== Default Template Tests ====================

    def test_default_template_title_format(self, generator, standard_issue, standard_device_info):
        """Test default template generates correct title format."""
        report = generator.generate_report(standard_issue, standard_device_info, 'default')

        expected_title = 'HIGH: Memory Leak in Video Service'
        assert report['title'] == expected_title, f"Expected '{expected_title}', got '{report['title']}'"

    def test_default_template_contains_all_sections(self, generator, standard_issue, standard_device_info):
        """Test default template contains all required sections."""
        report = generator.generate_report(standard_issue, standard_device_info, 'default')
        description = report['description']

        required_sections = [
            '## Description',
            '## Environment',
            '## Error Details',
            '## Log Excerpt',
            '## Affected Lines',
            '## Steps to Reproduce',
            '## Expected Behavior',
            '## Actual Behavior',
            '## Additional Notes',
        ]

        for section in required_sections:
            assert section in description, f"Missing section: {section}"

    def test_default_template_environment_info(self, generator, standard_issue, standard_device_info):
        """Test default template populates environment info correctly."""
        report = generator.generate_report(standard_issue, standard_device_info, 'default')
        description = report['description']

        assert '- Device: Camera-X100' in description
        assert '- Firmware: 2.1.4' in description
        assert '- Serial: CAM-2024-001234' in description

    def test_default_template_error_details(self, generator, standard_issue, standard_device_info):
        """Test default template populates error details correctly."""
        report = generator.generate_report(standard_issue, standard_device_info, 'default')
        description = report['description']

        assert '- Category: memory' in description
        assert '- Occurrence Count: 47' in description

    def test_default_template_confidence_score(self, generator, standard_issue, standard_device_info):
        """Test default template includes confidence score as percentage."""
        report = generator.generate_report(standard_issue, standard_device_info, 'default')

        assert 'Confidence Score: 95%' in report['description']

    # ==================== Jira Template Tests ====================

    def test_jira_template_title_format(self, generator, standard_issue, standard_device_info):
        """Test Jira template generates correct title format with brackets."""
        report = generator.generate_report(standard_issue, standard_device_info, 'jira')

        expected_title = '[HIGH] Memory Leak in Video Service'
        assert report['title'] == expected_title

    def test_jira_template_markup_syntax(self, generator, standard_issue, standard_device_info):
        """Test Jira template uses Jira wiki markup syntax."""
        report = generator.generate_report(standard_issue, standard_device_info, 'jira')
        description = report['description']

        # Jira-specific markup
        assert 'h2. Description' in description
        assert 'h2. Environment' in description
        assert '||Property||Value||' in description
        assert '{code}' in description
        assert '_Confidence Score:' in description

    def test_jira_template_table_format(self, generator, standard_issue, standard_device_info):
        """Test Jira template uses correct table format."""
        report = generator.generate_report(standard_issue, standard_device_info, 'jira')
        description = report['description']

        assert '|Category|memory|' in description
        assert '|Occurrences|47|' in description

    def test_jira_template_list_format(self, generator, standard_issue, standard_device_info):
        """Test Jira template uses correct list format."""
        report = generator.generate_report(standard_issue, standard_device_info, 'jira')
        description = report['description']

        assert '* *Device:* Camera-X100' in description
        assert '# [Describe the actions' in description  # Numbered list

    def test_jira_template_auto_generated_note(self, generator, standard_issue, standard_device_info):
        """Test Jira template includes auto-generated attribution."""
        report = generator.generate_report(standard_issue, standard_device_info, 'jira')

        assert '_Auto-generated by Sentinel Logger_' in report['description']

    # ==================== GitHub Template Tests ====================

    def test_github_template_title_format(self, generator, standard_issue, standard_device_info):
        """Test GitHub template uses plain title without severity prefix."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')

        expected_title = 'Memory Leak in Video Service'
        assert report['title'] == expected_title

    def test_github_template_markdown_syntax(self, generator, standard_issue, standard_device_info):
        """Test GitHub template uses proper GitHub Flavored Markdown."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')
        description = report['description']

        # GitHub markdown headers
        assert '### Description' in description
        assert '### Environment' in description
        assert '### Error Details' in description
        assert '### Log Excerpt' in description
        assert '### Steps to Reproduce' in description

    def test_github_template_table_format(self, generator, standard_issue, standard_device_info):
        """Test GitHub template uses proper markdown table format."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')
        description = report['description']

        assert '| Property | Value |' in description
        assert '|----------|-------|' in description
        assert '| Device | Camera-X100 |' in description

    def test_github_template_checkboxes(self, generator, standard_issue, standard_device_info):
        """Test GitHub template includes task checkboxes for steps."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')
        description = report['description']

        assert '1. [ ] Step 1' in description
        assert '2. [ ] Step 2' in description
        assert '3. [ ] Step 3' in description

    def test_github_template_footer(self, generator, standard_issue, standard_device_info):
        """Test GitHub template includes proper footer with sub tag."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')

        assert '<sub>Confidence Score:' in report['description']
        assert 'Auto-generated by Sentinel Logger</sub>' in report['description']

    def test_github_template_severity_in_body(self, generator, standard_issue, standard_device_info):
        """Test GitHub template includes severity in body since not in title."""
        report = generator.generate_report(standard_issue, standard_device_info, 'github')
        description = report['description']

        assert '**Severity:** HIGH' in description

    # ==================== Minimal Template Tests ====================

    def test_minimal_template_title_format(self, generator, standard_issue, standard_device_info):
        """Test minimal template uses plain title."""
        report = generator.generate_report(standard_issue, standard_device_info, 'minimal')

        expected_title = 'Memory Leak in Video Service'
        assert report['title'] == expected_title

    def test_minimal_template_brevity(self, generator, standard_issue, standard_device_info):
        """Test minimal template is concise without extra sections."""
        report = generator.generate_report(standard_issue, standard_device_info, 'minimal')
        description = report['description']

        # Should NOT contain these extended sections
        assert '## Steps to Reproduce' not in description
        assert '## Expected Behavior' not in description
        assert '## Additional Notes' not in description
        assert '## Environment' not in description

    def test_minimal_template_essential_info(self, generator, standard_issue, standard_device_info):
        """Test minimal template contains essential information."""
        report = generator.generate_report(standard_issue, standard_device_info, 'minimal')
        description = report['description']

        assert 'Category: memory' in description
        assert 'Severity: HIGH' in description
        assert 'Occurrences: 47' in description
        assert 'Time Range:' in description
        assert 'Log Context:' in description

    def test_minimal_template_no_confidence_score(self, generator, standard_issue, standard_device_info):
        """Test minimal template does not include confidence score."""
        report = generator.generate_report(standard_issue, standard_device_info, 'minimal')

        assert 'Confidence Score' not in report['description']

    # ==================== Template Fallback Tests ====================

    def test_invalid_template_falls_back_to_default(self, generator, standard_issue, standard_device_info):
        """Test that invalid template name falls back to default."""
        report = generator.generate_report(standard_issue, standard_device_info, 'nonexistent_template')

        # Should use default template format
        assert report['title'].startswith('HIGH:')
        assert '## Description' in report['description']


class TestBugReportGeneratorExportFormats:
    """Test cases for all export formats."""

    @pytest.fixture
    def generator(self):
        return BugReportGenerator()

    @pytest.fixture
    def standard_report(self, generator):
        """Create a standard report for export testing."""
        issue = {
            'title': 'Test Issue',
            'description': 'Test description for export',
            'severity': 'MEDIUM',
            'category': 'test',
            'first_occurrence': datetime(2024, 1, 15, 10, 0, 0),
            'last_occurrence': datetime(2024, 1, 15, 12, 0, 0),
            'occurrence_count': 5,
            'affected_lines': [10, 11, 12],
            'context': 'Sample log context',
            'confidence_score': 0.8,
        }
        return generator.generate_report(issue, {'model': 'TestDevice'}, 'default')

    # ==================== JSON Export Tests ====================

    def test_export_json_valid_format(self, generator, standard_report):
        """Test JSON export produces valid JSON."""
        json_output = generator.export_to_json(standard_report)

        # Should be parseable
        parsed = json.loads(json_output)
        assert isinstance(parsed, dict)

    def test_export_json_contains_all_fields(self, generator, standard_report):
        """Test JSON export contains all report fields."""
        json_output = generator.export_to_json(standard_report)
        parsed = json.loads(json_output)

        required_fields = [
            'title', 'description', 'severity', 'category',
            'steps_to_reproduce', 'expected_behavior', 'actual_behavior',
            'environment', 'log_snippets', 'template_used', 'created_at'
        ]

        for field in required_fields:
            assert field in parsed, f"Missing field in JSON: {field}"

    def test_export_json_is_indented(self, generator, standard_report):
        """Test JSON export is pretty-printed with indentation."""
        json_output = generator.export_to_json(standard_report)

        # Pretty-printed JSON has newlines
        assert '\n' in json_output
        # Check for 2-space indentation
        assert '  ' in json_output

    def test_export_json_preserves_nested_data(self, generator, standard_report):
        """Test JSON export preserves nested data structures."""
        json_output = generator.export_to_json(standard_report)
        parsed = json.loads(json_output)

        # Environment is stored as JSON string in the report
        env = json.loads(parsed['environment'])
        assert isinstance(env, dict)

    # ==================== Markdown Export Tests ====================

    def test_export_markdown_returns_description(self, generator, standard_report):
        """Test Markdown export returns the description content."""
        md_output = generator.export_to_markdown(standard_report)

        assert md_output == standard_report['description']

    def test_export_markdown_contains_sections(self, generator, standard_report):
        """Test Markdown export contains proper markdown sections."""
        md_output = generator.export_to_markdown(standard_report)

        assert '##' in md_output  # Contains headers
        assert '```' in md_output  # Contains code blocks

    def test_export_markdown_not_empty(self, generator, standard_report):
        """Test Markdown export is not empty."""
        md_output = generator.export_to_markdown(standard_report)

        assert len(md_output) > 0
        assert md_output.strip() != ''

    # ==================== Plain Text Export Tests ====================

    def test_export_text_structure(self, generator, standard_report):
        """Test plain text export has proper structure."""
        text_output = generator.export_to_text(standard_report)

        assert 'BUG REPORT' in text_output
        assert '==========' in text_output
        assert 'DESCRIPTION' in text_output
        assert '-----------' in text_output
        assert 'LOG SNIPPETS' in text_output

    def test_export_text_contains_title(self, generator, standard_report):
        """Test plain text export includes title."""
        text_output = generator.export_to_text(standard_report)

        assert 'Title:' in text_output
        assert standard_report['title'] in text_output

    def test_export_text_contains_metadata(self, generator, standard_report):
        """Test plain text export includes metadata."""
        text_output = generator.export_to_text(standard_report)

        assert 'Severity:' in text_output
        assert 'Category:' in text_output
        assert 'Created:' in text_output

    def test_export_text_no_leading_trailing_whitespace(self, generator, standard_report):
        """Test plain text export is properly trimmed."""
        text_output = generator.export_to_text(standard_report)

        # Should not start/end with whitespace
        assert text_output == text_output.strip()


class TestBugReportGeneratorFieldPopulation:
    """Test cases for auto-population of fields."""

    @pytest.fixture
    def generator(self):
        return BugReportGenerator()

    def test_datetime_formatting_from_datetime_objects(self, generator):
        """Test datetime objects are properly formatted."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'first_occurrence': datetime(2024, 6, 15, 14, 30, 45),
            'last_occurrence': datetime(2024, 6, 15, 16, 45, 30),
        }

        report = generator.generate_report(issue)

        assert '2024-06-15 14:30:45' in report['description']
        assert '2024-06-15 16:45:30' in report['description']

    def test_datetime_formatting_from_strings(self, generator):
        """Test string timestamps are passed through correctly."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'first_occurrence': '2024-06-15T14:30:45',
            'last_occurrence': '2024-06-15T16:45:30',
        }

        report = generator.generate_report(issue)

        assert '2024-06-15T14:30:45' in report['description']
        assert '2024-06-15T16:45:30' in report['description']

    def test_affected_lines_array_short(self, generator):
        """Test affected lines array formatting for short arrays."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'affected_lines': [5, 10, 15, 20],
        }

        report = generator.generate_report(issue)

        assert '5, 10, 15, 20' in report['description']

    def test_affected_lines_array_long(self, generator):
        """Test affected lines formatting for arrays > 10 elements."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'affected_lines': list(range(1, 51)),  # 50 lines
        }

        report = generator.generate_report(issue)

        assert 'Lines 1-50 (50 total)' in report['description']

    def test_affected_lines_from_json_string(self, generator):
        """Test affected lines parsing from JSON string."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'affected_lines': '[100, 101, 102]',
        }

        report = generator.generate_report(issue)

        assert '100, 101, 102' in report['description']

    def test_affected_lines_empty(self, generator):
        """Test affected lines shows N/A when empty."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'affected_lines': [],
        }

        report = generator.generate_report(issue)

        assert 'N/A' in report['description']

    def test_confidence_score_conversion_to_percentage(self, generator):
        """Test confidence score is converted from decimal to percentage."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'confidence_score': 0.75,
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'Confidence Score: 75%' in report['description']

    def test_additional_context_appended(self, generator):
        """Test additional context is appended to description."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(
            issue,
            additional_context='This is additional context for the bug report.'
        )

        assert '## Additional Context' in report['description']
        assert 'This is additional context for the bug report.' in report['description']

    def test_template_used_field_populated(self, generator):
        """Test template_used field is set correctly."""
        issue = {'title': 'Test', 'description': 'Test', 'severity': 'LOW'}

        for template in ['default', 'jira', 'github', 'minimal']:
            report = generator.generate_report(issue, template_name=template)
            assert report['template_used'] == template

    def test_created_at_is_iso_format(self, generator):
        """Test created_at timestamp is in ISO format."""
        issue = {'title': 'Test', 'description': 'Test', 'severity': 'LOW'}

        report = generator.generate_report(issue)

        # Should be parseable as ISO datetime
        datetime.fromisoformat(report['created_at'])

    def test_actual_behavior_mirrors_description(self, generator):
        """Test actual_behavior field mirrors issue description."""
        issue = {
            'title': 'Test',
            'description': 'The system crashed unexpectedly',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert report['actual_behavior'] == 'The system crashed unexpectedly'


class TestBugReportGeneratorEdgeCases:
    """Test cases for edge cases and error handling."""

    @pytest.fixture
    def generator(self):
        return BugReportGenerator()

    # ==================== Missing Data Tests ====================

    def test_missing_title_uses_default(self, generator):
        """Test missing title uses default value."""
        issue = {
            'description': 'Test description',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert 'Issue Detected' in report['title']

    def test_missing_description_uses_default(self, generator):
        """Test missing description uses default value."""
        issue = {
            'title': 'Test Title',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert 'No description available' in report['description']

    def test_missing_severity_uses_unknown(self, generator):
        """Test missing severity uses UNKNOWN."""
        issue = {
            'title': 'Test Title',
            'description': 'Test',
        }

        report = generator.generate_report(issue)

        assert report['severity'] is None  # Not in the issue dict

    def test_missing_category_uses_general(self, generator):
        """Test missing category uses 'general'."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'Category: general' in report['description']

    def test_missing_device_info_uses_unknown(self, generator):
        """Test missing device info uses Unknown values."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, device_info=None, template_name='default')

        assert 'Device: Unknown' in report['description']
        assert 'Firmware: Unknown' in report['description']
        assert 'Serial: Unknown' in report['description']

    def test_partial_device_info(self, generator):
        """Test partial device info fills in missing fields."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        partial_device = {'model': 'Camera-Y200'}
        report = generator.generate_report(issue, device_info=partial_device, template_name='default')

        assert 'Device: Camera-Y200' in report['description']
        assert 'Firmware: Unknown' in report['description']
        assert 'Serial: Unknown' in report['description']

    def test_missing_timestamps_uses_unknown(self, generator):
        """Test missing timestamps show Unknown."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'First Seen: Unknown' in report['description']
        assert 'Last Seen: Unknown' in report['description']

    def test_missing_occurrence_count_defaults_to_one(self, generator):
        """Test missing occurrence count defaults to 1."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'Occurrence Count: 1' in report['description']

    def test_missing_context_uses_default(self, generator):
        """Test missing log context uses default message."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'No log context available' in report['description']

    def test_empty_issue_dict(self, generator):
        """Test completely empty issue dict uses all defaults."""
        issue = {}

        report = generator.generate_report(issue)

        # Should not crash and should have defaults
        assert report['title'] is not None
        assert report['description'] is not None

    # ==================== Special Characters Tests ====================

    def test_special_characters_in_title(self, generator):
        """Test special characters in title are preserved."""
        issue = {
            'title': 'Error: <XML> & "JSON" parsing \'failed\'',
            'description': 'Test',
            'severity': 'HIGH',
        }

        report = generator.generate_report(issue)

        assert '<XML>' in report['title']
        assert '&' in report['title']
        assert '"JSON"' in report['title']
        assert "\'failed\'" in report['title']

    def test_special_characters_in_description(self, generator):
        """Test special characters in description are preserved."""
        issue = {
            'title': 'Test',
            'description': 'Error code: 0x1234 | Status: <FAILED> | Rate: 99.9%',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert '0x1234' in report['description']
        assert '<FAILED>' in report['description']
        assert '99.9%' in report['description']

    def test_markdown_special_characters(self, generator):
        """Test markdown special characters in content."""
        issue = {
            'title': 'Test',
            'description': 'Issue with **bold**, *italic*, and `code` markers',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue, template_name='github')

        assert '**bold**' in report['description']
        assert '*italic*' in report['description']
        assert '`code`' in report['description']

    def test_newlines_in_context(self, generator):
        """Test newlines in log context are preserved."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'context': 'Line 1\nLine 2\nLine 3',
        }

        report = generator.generate_report(issue)

        assert 'Line 1\nLine 2\nLine 3' in report['description']

    def test_curly_braces_in_log_context(self, generator):
        """Test curly braces in log context don't break formatting."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'context': '{"error": "connection_failed", "code": 500}',
        }

        # This could potentially break format() method
        report = generator.generate_report(issue)

        assert '{"error": "connection_failed"' in report['description']

    # ==================== Unicode Tests ====================

    def test_unicode_in_title(self, generator):
        """Test Unicode characters in title."""
        issue = {
            'title': 'Error: Japanese text',
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        # Title should be valid string
        assert isinstance(report['title'], str)

    def test_unicode_in_description(self, generator):
        """Test Unicode in description (Chinese, Japanese, Korean)."""
        issue = {
            'title': 'Test',
            'description': 'Log message: OK, GOOD, EXCELLENT',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert 'OK' in report['description']
        assert 'GOOD' in report['description']
        assert 'EXCELLENT' in report['description']

    def test_unicode_emojis(self, generator):
        """Test emoji characters in content."""
        issue = {
            'title': 'Test Error',
            'description': 'Status indicator found in log',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        # Should handle without error
        assert report['description'] is not None

    def test_unicode_device_info(self, generator):
        """Test Unicode in device info."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
        }

        device_info = {
            'model': 'Camera Model',
            'firmware_version': 'Version 2.0',
            'serial_number': 'SERIAL-12345',
        }

        report = generator.generate_report(issue, device_info=device_info, template_name='default')

        assert 'Camera Model' in report['description']

    # ==================== Boundary Tests ====================

    def test_very_long_title(self, generator):
        """Test handling of very long titles."""
        long_title = 'A' * 1000
        issue = {
            'title': long_title,
            'description': 'Test',
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert long_title in report['title']

    def test_very_long_description(self, generator):
        """Test handling of very long descriptions."""
        long_description = 'X' * 10000
        issue = {
            'title': 'Test',
            'description': long_description,
            'severity': 'LOW',
        }

        report = generator.generate_report(issue)

        assert long_description in report['description']

    def test_very_long_context(self, generator):
        """Test handling of very long log context."""
        long_context = 'LOG: ' + 'Y' * 10000
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'context': long_context,
        }

        report = generator.generate_report(issue)

        assert long_context in report['description']

    def test_zero_occurrence_count(self, generator):
        """Test zero occurrence count is displayed."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'occurrence_count': 0,
        }

        report = generator.generate_report(issue, template_name='default')

        assert 'Occurrence Count: 0' in report['description']

    def test_negative_confidence_score(self, generator):
        """Test negative confidence score handling."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'confidence_score': -0.5,
        }

        report = generator.generate_report(issue, template_name='default')

        # -0.5 * 100 = -50%
        assert 'Confidence Score: -50%' in report['description']

    def test_confidence_score_greater_than_one(self, generator):
        """Test confidence score > 1 handling."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'confidence_score': 1.5,
        }

        report = generator.generate_report(issue, template_name='default')

        # 1.5 * 100 = 150%
        assert 'Confidence Score: 150%' in report['description']

    def test_invalid_affected_lines_json(self, generator):
        """Test invalid JSON in affected_lines string is handled."""
        issue = {
            'title': 'Test',
            'description': 'Test',
            'severity': 'LOW',
            'affected_lines': 'not valid json',
        }

        # Should not crash
        report = generator.generate_report(issue)

        assert 'N/A' in report['description']


class TestSummaryReportGeneration:
    """Test cases for summary report generation."""

    @pytest.fixture
    def generator(self):
        return BugReportGenerator()

    @pytest.fixture
    def sample_issues(self):
        """Create sample issues for summary testing."""
        return [
            {
                'title': 'Critical Memory Leak',
                'description': 'Memory grows continuously',
                'severity': 'CRITICAL',
                'category': 'memory',
                'occurrence_count': 10,
            },
            {
                'title': 'High Crash Rate',
                'description': 'Service crashes frequently',
                'severity': 'HIGH',
                'category': 'crash',
                'occurrence_count': 5,
            },
            {
                'title': 'Medium Warning',
                'description': 'Some warning message',
                'severity': 'MEDIUM',
                'category': 'warning',
                'occurrence_count': 20,
            },
            {
                'title': 'Low Performance Issue',
                'description': 'Slight performance degradation',
                'severity': 'LOW',
                'category': 'performance',
                'occurrence_count': 100,
            },
            {
                'title': 'Info Level Note',
                'description': 'Informational message',
                'severity': 'INFO',
                'category': 'info',
                'occurrence_count': 50,
            },
        ]

    @pytest.fixture
    def sample_log_file_info(self):
        """Create sample log file info."""
        return {
            'filename': 'test_camera_log.log',
            'total_lines': 50000,
            'error_count': 1500,
            'warning_count': 3000,
        }

    def test_summary_report_header(self, generator, sample_issues, sample_log_file_info):
        """Test summary report has proper header."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '# Log Analysis Summary Report' in report
        assert 'Generated:' in report

    def test_summary_report_file_info(self, generator, sample_issues, sample_log_file_info):
        """Test summary report includes file information."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '## File Information' in report
        assert 'test_camera_log.log' in report
        assert '50,000' in report  # Formatted with comma
        assert '1,500' in report
        assert '3,000' in report

    def test_summary_report_total_issues(self, generator, sample_issues, sample_log_file_info):
        """Test summary report shows total issue count."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert 'Total Issues Detected: 5' in report

    def test_summary_report_severity_breakdown(self, generator, sample_issues, sample_log_file_info):
        """Test summary report breaks down by severity."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '### By Severity' in report
        assert '- CRITICAL: 1' in report
        assert '- HIGH: 1' in report
        assert '- MEDIUM: 1' in report
        assert '- LOW: 1' in report
        assert '- INFO: 1' in report

    def test_summary_report_category_breakdown(self, generator, sample_issues, sample_log_file_info):
        """Test summary report breaks down by category."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '### By Category' in report
        assert 'memory:' in report
        assert 'crash:' in report
        assert 'warning:' in report
        assert 'performance:' in report

    def test_summary_report_critical_high_details(self, generator, sample_issues, sample_log_file_info):
        """Test summary report includes critical/high issue details."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '## Critical and High Severity Issues' in report
        assert 'Critical Memory Leak' in report
        assert 'High Crash Rate' in report

    def test_summary_report_excludes_low_severity_details(self, generator, sample_issues, sample_log_file_info):
        """Test summary report doesn't show details for low/info severity."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        # These should only appear in category breakdown, not in detail section
        # Check that the detail section doesn't include LOW and INFO issues
        detail_section = report.split('## Critical and High Severity Issues')[-1]
        assert 'Low Performance Issue' not in detail_section
        assert 'Info Level Note' not in detail_section

    def test_summary_report_footer(self, generator, sample_issues, sample_log_file_info):
        """Test summary report has footer."""
        report = generator.generate_summary_report(sample_issues, sample_log_file_info)

        assert '*Generated by Sentinel Logger*' in report

    def test_summary_report_empty_issues(self, generator, sample_log_file_info):
        """Test summary report with no issues."""
        report = generator.generate_summary_report([], sample_log_file_info)

        assert 'Total Issues Detected: 0' in report
        assert '# Log Analysis Summary Report' in report

    def test_summary_report_only_critical(self, generator, sample_log_file_info):
        """Test summary with only critical issues."""
        issues = [
            {
                'title': 'Critical Issue 1',
                'description': 'Desc 1',
                'severity': 'CRITICAL',
                'category': 'crash',
                'occurrence_count': 1,
            },
            {
                'title': 'Critical Issue 2',
                'description': 'Desc 2',
                'severity': 'CRITICAL',
                'category': 'memory',
                'occurrence_count': 2,
            },
        ]

        report = generator.generate_summary_report(issues, sample_log_file_info)

        assert '- CRITICAL: 2' in report
        assert 'Critical Issue 1' in report
        assert 'Critical Issue 2' in report

    def test_summary_report_limits_to_ten_issues(self, generator, sample_log_file_info):
        """Test summary report limits detailed issues to 10."""
        # Create 15 high severity issues
        issues = [
            {
                'title': f'High Issue {i}',
                'description': f'Description {i}',
                'severity': 'HIGH',
                'category': 'test',
                'occurrence_count': i,
            }
            for i in range(1, 16)
        ]

        report = generator.generate_summary_report(issues, sample_log_file_info)

        # Should have 10 numbered issues in detail section
        assert '### 1. High Issue 1' in report
        assert '### 10. High Issue 10' in report
        # Issue 11-15 should not appear in numbered list
        assert '### 11.' not in report


class TestExportFormatEdgeCases:
    """Test edge cases for export formats."""

    @pytest.fixture
    def generator(self):
        return BugReportGenerator()

    def test_export_json_handles_datetime(self, generator):
        """Test JSON export handles datetime serialization."""
        report = {
            'title': 'Test',
            'created_at': datetime(2024, 1, 15, 10, 30, 0),
        }

        # Should not raise an error
        json_output = generator.export_to_json(report)

        # Should contain the datetime as string
        assert '2024-01-15' in json_output

    def test_export_json_handles_none_values(self, generator):
        """Test JSON export handles None values."""
        report = {
            'title': 'Test',
            'description': None,
            'severity': None,
        }

        json_output = generator.export_to_json(report)
        parsed = json.loads(json_output)

        assert parsed['description'] is None
        assert parsed['severity'] is None

    def test_export_text_handles_missing_fields(self, generator):
        """Test plain text export handles missing fields gracefully."""
        report = {}

        text_output = generator.export_to_text(report)

        assert 'Title: N/A' in text_output
        assert 'Severity: N/A' in text_output

    def test_export_markdown_handles_empty_description(self, generator):
        """Test Markdown export handles empty/missing description."""
        report = {'description': ''}

        md_output = generator.export_to_markdown(report)

        assert md_output == ''

    def test_export_markdown_handles_missing_description(self, generator):
        """Test Markdown export handles missing description key."""
        report = {}

        md_output = generator.export_to_markdown(report)

        assert md_output == ''
