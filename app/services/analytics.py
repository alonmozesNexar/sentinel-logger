"""
Analytics Service - Provides data for charts and visualizations
"""
from collections import defaultdict
from datetime import datetime
from typing import Dict, List


class AnalyticsService:
    """
    Generates analytics data for visualization in the web UI.
    Provides data formatted for Chart.js and similar libraries.
    """

    # Color schemes for charts
    SEVERITY_COLORS = {
        'CRITICAL': {'bg': 'rgba(220, 53, 69, 0.7)', 'border': 'rgb(220, 53, 69)'},
        'ERROR': {'bg': 'rgba(255, 99, 132, 0.7)', 'border': 'rgb(255, 99, 132)'},
        'WARNING': {'bg': 'rgba(255, 193, 7, 0.7)', 'border': 'rgb(255, 193, 7)'},
        'INFO': {'bg': 'rgba(23, 162, 184, 0.7)', 'border': 'rgb(23, 162, 184)'},
        'DEBUG': {'bg': 'rgba(108, 117, 125, 0.7)', 'border': 'rgb(108, 117, 125)'},
    }

    SERVICE_COLORS = [
        'rgba(54, 162, 235, 0.7)',
        'rgba(75, 192, 192, 0.7)',
        'rgba(153, 102, 255, 0.7)',
        'rgba(255, 159, 64, 0.7)',
        'rgba(255, 99, 132, 0.7)',
        'rgba(255, 206, 86, 0.7)',
        'rgba(231, 233, 237, 0.7)',
        'rgba(99, 255, 132, 0.7)',
    ]

    def __init__(self):
        pass

    def get_severity_distribution(self, entries: List[Dict]) -> Dict:
        """
        Get distribution of log entries by severity level.
        Returns data formatted for a pie/doughnut chart.
        """
        counts = defaultdict(int)
        for entry in entries:
            severity = entry.get('severity', 'INFO')
            counts[severity] += 1

        labels = []
        data = []
        background_colors = []
        border_colors = []

        for severity in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
            if counts[severity] > 0:
                labels.append(severity)
                data.append(counts[severity])
                colors = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS['INFO'])
                background_colors.append(colors['bg'])
                border_colors.append(colors['border'])

        return {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': background_colors,
                'borderColor': border_colors,
                'borderWidth': 1
            }]
        }

    def get_errors_timeline(self, entries: List[Dict], bucket_minutes: int = 10) -> Dict:
        """
        Get error counts over time.
        Returns data formatted for a line chart.
        """
        time_buckets = defaultdict(lambda: {'errors': 0, 'warnings': 0, 'total': 0})

        min_time = None
        max_time = None

        for entry in entries:
            timestamp = entry.get('timestamp')
            if not timestamp:
                continue

            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    continue

            # Track time range
            if not min_time or timestamp < min_time:
                min_time = timestamp
            if not max_time or timestamp > max_time:
                max_time = timestamp

            # Bucket by specified minutes
            bucket = timestamp.replace(
                minute=(timestamp.minute // bucket_minutes) * bucket_minutes,
                second=0,
                microsecond=0
            )
            bucket_key = bucket.isoformat()

            time_buckets[bucket_key]['total'] += 1

            severity = entry.get('severity', 'INFO')
            if severity in ['CRITICAL', 'ERROR']:
                time_buckets[bucket_key]['errors'] += 1
            elif severity == 'WARNING':
                time_buckets[bucket_key]['warnings'] += 1

        # Sort by time
        sorted_buckets = sorted(time_buckets.items())

        labels = [item[0] for item in sorted_buckets]
        # Format labels for display
        display_labels = []
        for label in labels:
            try:
                dt = datetime.fromisoformat(label)
                display_labels.append(dt.strftime('%H:%M'))
            except ValueError:
                display_labels.append(label)

        errors = [item[1]['errors'] for item in sorted_buckets]
        warnings = [item[1]['warnings'] for item in sorted_buckets]

        return {
            'labels': display_labels,
            'datasets': [
                {
                    'label': 'Errors',
                    'data': errors,
                    'borderColor': 'rgb(255, 99, 132)',
                    'backgroundColor': 'rgba(255, 99, 132, 0.1)',
                    'fill': True,
                    'tension': 0.4
                },
                {
                    'label': 'Warnings',
                    'data': warnings,
                    'borderColor': 'rgb(255, 193, 7)',
                    'backgroundColor': 'rgba(255, 193, 7, 0.1)',
                    'fill': True,
                    'tension': 0.4
                }
            ]
        }

    def get_service_distribution(self, entries: List[Dict]) -> Dict:
        """
        Get distribution of log entries by service.
        Returns data formatted for a bar chart.
        """
        service_counts = defaultdict(lambda: {'total': 0, 'errors': 0})

        for entry in entries:
            service = entry.get('service') or 'Unknown'
            service_counts[service]['total'] += 1

            severity = entry.get('severity', 'INFO')
            if severity in ['CRITICAL', 'ERROR']:
                service_counts[service]['errors'] += 1

        # Sort by total count
        sorted_services = sorted(service_counts.items(), key=lambda x: -x[1]['total'])[:10]

        labels = [item[0] for item in sorted_services]
        totals = [item[1]['total'] for item in sorted_services]
        errors = [item[1]['errors'] for item in sorted_services]

        return {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Total Entries',
                    'data': totals,
                    'backgroundColor': 'rgba(54, 162, 235, 0.7)',
                    'borderColor': 'rgb(54, 162, 235)',
                    'borderWidth': 1
                },
                {
                    'label': 'Errors',
                    'data': errors,
                    'backgroundColor': 'rgba(255, 99, 132, 0.7)',
                    'borderColor': 'rgb(255, 99, 132)',
                    'borderWidth': 1
                }
            ]
        }

    def get_hourly_distribution(self, entries: List[Dict]) -> Dict:
        """
        Get distribution of errors by hour of day.
        Returns data for a bar chart showing when errors occur most.
        """
        hourly_counts = {str(h).zfill(2): {'total': 0, 'errors': 0} for h in range(24)}

        for entry in entries:
            timestamp = entry.get('timestamp')
            if not timestamp:
                continue

            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    continue

            hour = str(timestamp.hour).zfill(2)
            hourly_counts[hour]['total'] += 1

            severity = entry.get('severity', 'INFO')
            if severity in ['CRITICAL', 'ERROR']:
                hourly_counts[hour]['errors'] += 1

        labels = [f"{h}:00" for h in sorted(hourly_counts.keys())]
        errors = [hourly_counts[h]['errors'] for h in sorted(hourly_counts.keys())]

        return {
            'labels': labels,
            'datasets': [{
                'label': 'Errors by Hour',
                'data': errors,
                'backgroundColor': 'rgba(255, 99, 132, 0.7)',
                'borderColor': 'rgb(255, 99, 132)',
                'borderWidth': 1
            }]
        }

    def get_issue_category_distribution(self, issues: List[Dict]) -> Dict:
        """
        Get distribution of issues by category.
        Returns data for a horizontal bar chart.
        """
        category_counts = defaultdict(int)

        for issue in issues:
            category = issue.get('category', 'unknown')
            category_counts[category] += 1

        # Sort by count
        sorted_categories = sorted(category_counts.items(), key=lambda x: -x[1])

        labels = [item[0].replace('_', ' ').title() for item in sorted_categories]
        counts = [item[1] for item in sorted_categories]

        # Assign colors
        colors = self.SERVICE_COLORS[:len(labels)]
        while len(colors) < len(labels):
            colors.extend(self.SERVICE_COLORS)

        return {
            'labels': labels,
            'datasets': [{
                'label': 'Issue Count',
                'data': counts,
                'backgroundColor': colors[:len(labels)],
                'borderWidth': 1
            }]
        }

    def get_dashboard_summary(self, entries: List[Dict], issues: List[Dict]) -> Dict:
        """
        Get summary statistics for dashboard display.
        """
        total_entries = len(entries)

        severity_counts = defaultdict(int)
        for entry in entries:
            severity_counts[entry.get('severity', 'INFO')] += 1

        # Calculate error rate
        error_count = severity_counts.get('CRITICAL', 0) + severity_counts.get('ERROR', 0)
        error_rate = (error_count / total_entries * 100) if total_entries > 0 else 0

        # Issue counts by severity
        issue_severity_counts = defaultdict(int)
        for issue in issues:
            issue_severity_counts[issue.get('severity', 'UNKNOWN')] += 1

        # Time range
        timestamps = [e['timestamp'] for e in entries if e.get('timestamp')]
        if timestamps:
            # Handle both datetime objects and strings
            parsed_timestamps = []
            for ts in timestamps:
                if isinstance(ts, datetime):
                    parsed_timestamps.append(ts)
                elif isinstance(ts, str):
                    try:
                        parsed_timestamps.append(datetime.fromisoformat(ts))
                    except ValueError:
                        pass

            if parsed_timestamps:
                time_range = {
                    'start': min(parsed_timestamps).isoformat(),
                    'end': max(parsed_timestamps).isoformat(),
                    'duration_hours': round((max(parsed_timestamps) - min(parsed_timestamps)).total_seconds() / 3600, 2)
                }
            else:
                time_range = None
        else:
            time_range = None

        return {
            'total_entries': total_entries,
            'severity_counts': dict(severity_counts),
            'error_count': error_count,
            'warning_count': severity_counts.get('WARNING', 0),
            'error_rate': round(error_rate, 2),
            'total_issues': len(issues),
            'critical_issues': issue_severity_counts.get('CRITICAL', 0),
            'high_issues': issue_severity_counts.get('HIGH', 0),
            'time_range': time_range
        }

    def get_all_charts(self, entries: List[Dict], issues: List[Dict]) -> Dict:
        """
        Get all chart data in one call for dashboard.
        """
        return {
            'severity_distribution': self.get_severity_distribution(entries),
            'errors_timeline': self.get_errors_timeline(entries),
            'service_distribution': self.get_service_distribution(entries),
            'hourly_distribution': self.get_hourly_distribution(entries),
            'issue_categories': self.get_issue_category_distribution(issues),
            'summary': self.get_dashboard_summary(entries, issues)
        }
