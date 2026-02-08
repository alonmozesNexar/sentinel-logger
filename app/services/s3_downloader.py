"""
S3 Downloader Service for NexarOne Logs
Based on get-logs.sh script - fetches logs from sdk-logs-prod bucket
Supports AWS SSO profiles
"""
import os
import gzip
import configparser
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from io import BytesIO

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

# Boto3 client config with short timeouts to avoid hanging
_BOTO_CONFIG = BotoConfig(
    connect_timeout=5,
    read_timeout=10,
    retries={'max_attempts': 1}
)


class S3Downloader:
    """
    Downloads camera logs from S3 bucket.
    Bucket structure: s3://sdk-logs-prod/{serial_number}/{date}*
    Supports AWS SSO profiles.
    """

    def __init__(
        self,
        bucket: str = None,
        region: str = None,
        profile: str = None,
        access_key: str = None,
        secret_key: str = None
    ):
        self.bucket = bucket or os.environ.get('S3_BUCKET', 'sdk-logs-prod')
        self.region = region or os.environ.get('S3_REGION', 'us-east-1')
        self.profile = profile or os.environ.get('AWS_PROFILE')
        self.s3_client = None
        self.session = None
        self._init_error = None

        # Try to initialize S3 client
        self._init_client(access_key, secret_key)

    def _make_client(self, session):
        """Create an S3 client with timeout config from a boto3 session."""
        return session.client('s3', config=_BOTO_CONFIG)

    def _init_client(self, access_key: str = None, secret_key: str = None):
        """Initialize S3 client with various auth methods."""
        try:
            # Method 1: Explicit credentials
            if access_key and secret_key:
                self.session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=self.region
                )
                self.s3_client = self._make_client(self.session)
                return

            # Method 2: AWS Profile (SSO or static)
            if self.profile:
                try:
                    self.session = boto3.Session(
                        profile_name=self.profile,
                        region_name=self.region
                    )
                    self.s3_client = self._make_client(self.session)
                    return
                except ProfileNotFound:
                    self._init_error = f"AWS profile '{self.profile}' not found"

            # Method 3: Try each available profile (with timeout protection)
            available_profiles = self._get_available_profiles()
            for profile_name in available_profiles:
                try:
                    session = boto3.Session(
                        profile_name=profile_name,
                        region_name=self.region
                    )
                    client = self._make_client(session)
                    # Test if it works — timeout config prevents hanging
                    client.head_bucket(Bucket=self.bucket)
                    self.session = session
                    self.s3_client = client
                    self.profile = profile_name
                    return
                except Exception:
                    continue

            # Method 4: Default credentials chain (env vars, IAM role, etc.)
            self.session = boto3.Session(region_name=self.region)
            self.s3_client = self._make_client(self.session)

        except Exception as e:
            self._init_error = str(e)
            # Create a dummy client that will fail gracefully
            self.session = boto3.Session(region_name=self.region)
            self.s3_client = self._make_client(self.session)

    def _get_available_profiles(self) -> List[str]:
        """Get list of available AWS profiles from config."""
        profiles = []
        config_path = Path.home() / '.aws' / 'config'

        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)

            for section in config.sections():
                if section.startswith('profile '):
                    profile_name = section.replace('profile ', '')
                    profiles.append(profile_name)
                elif section == 'default':
                    profiles.insert(0, 'default')

        return profiles

    def get_available_profiles(self) -> List[Dict]:
        """Get list of available AWS profiles with details."""
        profiles = []
        config_path = Path.home() / '.aws' / 'config'

        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)

            for section in config.sections():
                if section.startswith('profile '):
                    profile_name = section.replace('profile ', '')
                    profile_data = dict(config[section])
                    profiles.append({
                        'name': profile_name,
                        'region': profile_data.get('region', 'us-east-1'),
                        'is_sso': 'sso_start_url' in profile_data or 'sso_session' in profile_data,
                        'account_id': profile_data.get('sso_account_id', ''),
                        'role': profile_data.get('sso_role_name', '')
                    })

        return profiles

    def set_profile(self, profile_name: str) -> bool:
        """Switch to a different AWS profile."""
        try:
            self.session = boto3.Session(
                profile_name=profile_name,
                region_name=self.region
            )
            self.s3_client = self._make_client(self.session)
            self.profile = profile_name
            self._init_error = None
            return True
        except Exception as e:
            self._init_error = str(e)
            return False

    def is_available(self) -> bool:
        """Check if S3 connection is working."""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket)
            return True
        except Exception:
            return False

    def _try_refresh_credentials(self) -> bool:
        """Try to refresh credentials by reinitializing the client."""
        old_profile = self.profile
        self._init_client()
        # If we had a profile before, try it again (SSO credentials may have been refreshed)
        if old_profile:
            try:
                self.session = boto3.Session(
                    profile_name=old_profile,
                    region_name=self.region
                )
                self.s3_client = self._make_client(self.session)
                self.s3_client.head_bucket(Bucket=self.bucket)
                self.profile = old_profile
                return True
            except Exception:
                pass
        return self.is_available()

    def list_logs(
        self,
        serial_number: str,
        date: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        List available log files for a camera.

        Args:
            serial_number: Camera serial number
            date: Optional date filter (yyyy-mm-dd or yyyy-mm)
            limit: Max number of files to return

        Returns:
            List of dicts with file info: key, size, last_modified
        """
        prefix = f"{serial_number}/"
        if date:
            prefix = f"{serial_number}/{date}"

        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            files = []

            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get('Contents', []):
                    # Extract date folder from path: serial/date_folder/filename
                    key_parts = obj['Key'].split('/')
                    date_folder = key_parts[1] if len(key_parts) > 2 else ''
                    files.append({
                        'key': obj['Key'],
                        'filename': obj['Key'].split('/')[-1],
                        'folder': date_folder,
                        'size': obj['Size'],
                        'size_human': self._format_size(obj['Size']),
                        'last_modified': obj['LastModified'].isoformat(),
                        'date': date_folder
                    })
                    if len(files) >= limit:
                        break
                if len(files) >= limit:
                    break

            # Sort by last modified (newest first)
            files.sort(key=lambda x: x['last_modified'], reverse=True)
            return files

        except ClientError as e:
            raise Exception(f"Failed to list logs: {e.response['Error']['Message']}")
        except NoCredentialsError:
            raise Exception("AWS credentials not configured. Run 'aws sso login' or set credentials.")

    def get_log_dates(self, serial_number: str) -> List[str]:
        """
        Get unique dates that have logs for a camera.

        Args:
            serial_number: Camera serial number

        Returns:
            List of dates (yyyy-mm-dd) with available logs
        """
        files = self.list_logs(serial_number, limit=1000)
        dates = set()
        for f in files:
            if f['date']:
                dates.add(f['date'])
        return sorted(list(dates), reverse=True)

    def download_log(
        self,
        serial_number: str,
        filename: str = None,
        date: str = None,
        decompress: bool = True
    ) -> Tuple[BytesIO, Dict]:
        """
        Download a specific log file.

        Args:
            serial_number: Camera serial number
            filename: Specific filename or full S3 key to download
            date: Date prefix to filter (if filename not provided, downloads first match)
            decompress: Auto-decompress .gz files

        Returns:
            Tuple of (file content as BytesIO, metadata dict)
        """
        if filename:
            # Check if filename is already a full S3 key (contains serial number)
            if filename.startswith(serial_number + '/'):
                key = filename
                filename = filename.split('/')[-1]
            elif '/' in filename:
                # It's a relative path like "folder/filename"
                key = f"{serial_number}/{filename}"
                filename = filename.split('/')[-1]
            else:
                key = f"{serial_number}/{filename}"
        else:
            # Find first file matching date
            files = self.list_logs(serial_number, date=date, limit=1)
            if not files:
                raise Exception(f"No logs found for {serial_number}" + (f" on {date}" if date else ""))
            key = files[0]['key']
            filename = files[0]['filename']

        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=key)
            content = response['Body'].read()

            metadata = {
                'key': key,
                'filename': filename,
                'size': response['ContentLength'],
                'last_modified': response['LastModified'].isoformat(),
                'content_type': response.get('ContentType', 'application/octet-stream'),
                'serial_number': serial_number
            }

            # Decompress if .gz file
            if decompress and filename.endswith('.gz'):
                try:
                    content = gzip.decompress(content)
                    metadata['decompressed'] = True
                    metadata['original_filename'] = filename
                    metadata['filename'] = filename[:-3]  # Remove .gz
                except gzip.BadGzipFile:
                    metadata['decompressed'] = False

            return BytesIO(content), metadata

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchKey':
                raise Exception(f"Log file not found: {key}")
            raise Exception(f"Failed to download: {e.response['Error']['Message']}")
        except NoCredentialsError:
            raise Exception("AWS credentials not configured. Run 'aws sso login' or set credentials.")

    def download_logs_by_date(
        self,
        serial_number: str,
        date: str,
        decompress: bool = True
    ) -> List[Tuple[BytesIO, Dict]]:
        """
        Download all logs for a specific date.

        Args:
            serial_number: Camera serial number
            date: Date to download (yyyy-mm-dd)
            decompress: Auto-decompress .gz files

        Returns:
            List of (content, metadata) tuples
        """
        files = self.list_logs(serial_number, date=date)
        results = []

        for f in files:
            try:
                content, metadata = self.download_log(
                    serial_number,
                    filename=f['filename'],
                    decompress=decompress
                )
                results.append((content, metadata))
            except Exception as e:
                # Log error but continue with other files
                results.append((None, {'error': str(e), 'filename': f['filename']}))

        return results

    def get_status(self) -> Dict:
        """Get S3 connection status and info. Auto-refreshes credentials if expired."""
        available_profiles = self.get_available_profiles()

        def make_status(available: bool, message: str) -> Dict:
            return {
                'available': available,
                'bucket': self.bucket,
                'region': self.region,
                'profile': self.profile,
                'profiles': available_profiles,
                'init_error': self._init_error,
                'message': message
            }

        # If initialization already failed, report that immediately
        if self._init_error and not self.s3_client:
            return make_status(False, f"S3 init failed: {self._init_error}")

        try:
            self.s3_client.head_bucket(Bucket=self.bucket)
            return make_status(True, f'Connected to S3' + (f' using profile: {self.profile}' if self.profile else ''))
        except (NoCredentialsError, ClientError) as e:
            # Check if this is an expired token error
            is_expired = isinstance(e, NoCredentialsError)
            if isinstance(e, ClientError):
                error_msg = e.response['Error']['Message']
                is_expired = 'ExpiredToken' in error_msg or 'InvalidToken' in error_msg

            # Try to auto-refresh credentials (user may have run aws sso login)
            if self._try_refresh_credentials():
                return make_status(True, f'Connected to S3' + (f' using profile: {self.profile}' if self.profile else ''))

            # Still failed - return appropriate error message
            sso_profiles = [p for p in available_profiles if p.get('is_sso')]
            if isinstance(e, NoCredentialsError) or is_expired:
                if sso_profiles:
                    msg = f"AWS SSO session expired. Run: aws sso login --profile {sso_profiles[0]['name']}"
                else:
                    msg = 'AWS credentials not configured. Use the S3 Credentials form, set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or configure AWS SSO.'
            else:
                msg = f"S3 error: {e.response['Error']['Message']}"
            return make_status(False, msg)
        except Exception as e:
            # Try to auto-refresh for any other error too
            if self._try_refresh_credentials():
                return make_status(True, f'Connected to S3' + (f' using profile: {self.profile}' if self.profile else ''))
            return make_status(False, f"S3 connection error: {str(e)}")

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"


# Singleton instance
_s3_downloader_instance = None


def get_s3_downloader(profile: str = None) -> S3Downloader:
    """Get or create S3 downloader singleton."""
    global _s3_downloader_instance
    if _s3_downloader_instance is None:
        _s3_downloader_instance = S3Downloader(profile=profile)
    elif profile and profile != _s3_downloader_instance.profile:
        _s3_downloader_instance.set_profile(profile)
    return _s3_downloader_instance


def reset_s3_downloader():
    """Reset S3 downloader (for testing or reconnection)."""
    global _s3_downloader_instance
    _s3_downloader_instance = None
