"""
Camera Log Downloader Service
Downloads log files from camera devices via SSH
"""
import logging
import re
import shlex
import socket
from datetime import datetime
from io import BytesIO
from pathlib import Path

import os
import subprocess

import paramiko

logger = logging.getLogger(__name__)


# Cache the AWS firmware password
_cached_fw_password = None

def _get_fw_password():
    """Get firmware password from AWS SSM Parameter Store (cached)."""
    global _cached_fw_password
    if _cached_fw_password is not None:
        return _cached_fw_password
    try:
        env = os.environ.copy()
        env['AWS_PROFILE'] = 'fw-ops'
        cmd = [
            'aws', 'ssm', 'get-parameter',
            '--name', '/lockness/grant/fw-developer/prod/fw-password/key',
            '--with-decryption',
            '--region', 'us-west-1',
            '--query', 'Parameter.Value',
            '--output', 'text'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
        if result.returncode == 0:
            _cached_fw_password = result.stdout.strip()
            return _cached_fw_password
    except Exception:
        pass
    return None

# Allowed directories for listing files (security: prevent directory traversal)
ALLOWED_LOG_DIRECTORIES = ['/var/log', '/data/log', '/tmp', '/var/tmp']

def _sanitize_path(path: str) -> str:
    """
    Sanitize a file path to prevent command injection and directory traversal.
    Returns the sanitized path or raises ValueError if path is invalid.
    """
    # Remove any shell metacharacters
    if not path:
        raise ValueError("Path cannot be empty")

    # Check for command injection attempts
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in path:
            raise ValueError(f"Invalid character in path: {char}")

    # Normalize the path and check for directory traversal
    normalized = str(Path(path).resolve()) if not path.startswith('/') else path

    # Ensure no directory traversal attempts
    if '..' in path:
        raise ValueError("Directory traversal not allowed")

    return path


def _is_allowed_directory(directory: str) -> bool:
    """Check if directory is in the allowed list for listing operations."""
    normalized = directory.rstrip('/')
    return any(normalized == allowed or normalized.startswith(allowed + '/')
               for allowed in ALLOWED_LOG_DIRECTORIES)


class CameraDownloader:
    """Service to download logs from camera via SSH"""

    def __init__(self, host=None, username=None, password=None, port=22, timeout=30):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.client = None
        self.transport = None
        self.auth_method = None

    def connect(self):
        """Establish SSH connection to camera with retry and known_hosts cleanup"""
        import time

        # Remove stale known_hosts entry — different cameras share the same IP
        try:
            subprocess.run(
                ['ssh-keygen', '-R', self.host],
                capture_output=True, timeout=5
            )
            logger.debug(f"Cleared known_hosts entry for {self.host}")
        except Exception as e:
            logger.debug(f"ssh-keygen -R {self.host} skipped: {e}")

        auth_methods = [
            ("ssh_key", dict(look_for_keys=True, allow_agent=True)),
        ]

        # Try AWS firmware password (most cameras use this)
        fw_password = _get_fw_password()
        if fw_password:
            auth_methods.append(("aws_ssm", dict(
                password=fw_password, look_for_keys=False, allow_agent=False
            )))

        # User-provided password last
        if self.password:
            auth_methods.append(("password", dict(
                password=self.password, look_for_keys=False, allow_agent=False
            )))

        last_error = None

        for method_name, kwargs in auth_methods:
            for attempt in range(3):
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
                try:
                    self.client.connect(
                        hostname=self.host,
                        port=self.port,
                        username=self.username,
                        timeout=self.timeout,
                        banner_timeout=self.timeout,
                        **kwargs
                    )
                    self.transport = self.client.get_transport()
                    self.auth_method = method_name
                    return True, f"Connected successfully (using {method_name})"
                except paramiko.AuthenticationException as e:
                    last_error = e
                    try:
                        self.client.close()
                    except Exception:
                        pass
                    self.client = None
                    break  # Don't retry auth failures, try next method
                except (paramiko.SSHException, socket.error, OSError, ConnectionError) as e:
                    last_error = e
                    try:
                        self.client.close()
                    except Exception:
                        pass
                    self.client = None
                    if attempt < 2:
                        time.sleep(1 * (attempt + 1))
                        continue
                    break

        # All methods failed — return user-friendly error
        if isinstance(last_error, paramiko.AuthenticationException):
            return False, f"Authentication failed for {self.username}@{self.host}. Check username and password."
        error_msg = str(last_error) if last_error else "Unknown error"
        if 'Connection reset by peer' in error_msg or 'banner' in error_msg.lower():
            return False, f"Camera SSH refused the connection ({self.host}). Try again in a few seconds, or reboot the camera."
        elif 'Connection refused' in error_msg:
            return False, f"SSH port {self.port} is not open on {self.host}. Ensure SSH is enabled on the camera."
        elif 'timed out' in error_msg.lower() or isinstance(last_error, socket.timeout):
            return False, "Connection timed out. Is the camera on and connected to WiFi?"
        elif 'No route to host' in error_msg:
            return False, f"Cannot reach {self.host}. Make sure you're connected to the camera's WiFi network."
        else:
            logger.error(f"SSH connection failed to {self.host}: {error_msg}")
            return False, f"Connection failed: {error_msg}"

    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.client = None
        if self.transport:
            self.transport.close()
            self.transport = None

    def test_connection(self):
        """Test if camera is reachable"""
        success, message = self.connect()
        if success:
            self.disconnect()
        return success, message

    def download_log(self, remote_path='/var/log/messages'):
        """Download log file from camera using paramiko SSH"""
        try:
            # Sanitize the remote path to prevent command injection
            try:
                remote_path = _sanitize_path(remote_path)
            except ValueError as e:
                return None, f"Invalid path: {str(e)}"

            # Connect if not already connected
            if not self.client or not self.transport:
                success, msg = self.connect()
                if not success:
                    return None, msg

            # Execute cat command to read the file using shell quoting for safety
            try:
                safe_path = shlex.quote(remote_path)
                stdin, stdout, stderr = self.client.exec_command(
                    f'cat {safe_path}',
                    timeout=120
                )
                output = stdout.read()
                error_output = stderr.read().decode('utf-8', errors='ignore').strip()

                if error_output:
                    if 'No such file' in error_output:
                        return None, f"Log file not found on camera: {remote_path}"
                    if 'Permission denied' in error_output:
                        return None, f"Permission denied reading: {remote_path}"
                    if not output:
                        return None, f"Failed to read file: {error_output}"

                if not output:
                    return None, f"Log file empty or not found: {remote_path}"

                file_buffer = BytesIO(output)
                file_size = len(output)

                return {
                    'content': file_buffer,
                    'size': file_size,
                    'remote_path': remote_path,
                    'filename': Path(remote_path).name,
                    'downloaded_at': datetime.now().isoformat()
                }, "Download successful"

            except socket.timeout:
                return None, "Download timed out. The log file may be too large."

        except socket.timeout:
            return None, f"Connection timed out. Camera at {self.host} is not responding."
        except paramiko.AuthenticationException:
            return None, "SSH authentication failed. Check username/password."
        except paramiko.SSHException as e:
            return None, f"SSH error: {str(e)}"
        except socket.error as e:
            return None, f"Network error: {str(e)}. Is the camera reachable at {self.host}?"
        except Exception as e:
            return None, f"Download failed: {str(e)}"

    def list_log_files(self, directory='/var/log'):
        """List available log files on camera"""
        try:
            # Validate directory is in allowed list (security)
            if not _is_allowed_directory(directory):
                logger.warning(f"Attempted access to non-allowed directory: {directory}")
                return None, f"Directory not allowed. Permitted directories: {', '.join(ALLOWED_LOG_DIRECTORIES)}"

            # Sanitize directory path
            try:
                directory = _sanitize_path(directory)
            except ValueError as e:
                return None, f"Invalid directory: {str(e)}"

            # Use shell quoting for safety
            safe_directory = shlex.quote(directory)
            output = self._exec_command(f'ls -la {safe_directory}')
            if not output:
                return None, f"Failed to list files in {directory}"

            files = []
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) >= 9:
                    filename = parts[-1]
                    # Check for log files
                    if any(filename.endswith(ext) for ext in ['.log', '.txt', '.out', '.err']) or \
                       filename in ['messages', 'messages.1', 'syslog', 'dmesg', 'kern.log', 'auth.log']:
                        try:
                            size = int(parts[4])
                        except (ValueError, IndexError):
                            size = 0
                        files.append({
                            'name': filename,
                            'path': f"{directory}/{filename}",
                            'size': size,
                            'modified': None
                        })

            # Sort by size (largest first)
            files.sort(key=lambda x: x['size'], reverse=True)

            return files, "Listed successfully"

        except Exception as e:
            return None, f"Failed to list files: {str(e)}"

    def _exec_command(self, command):
        """Execute a command on the remote camera using paramiko SSH"""
        try:
            # Connect if not already connected
            if not self.client or not self.transport:
                success, msg = self.connect()
                if not success:
                    logger.error(f"Failed to connect for command execution: {msg}")
                    return ""

            # Execute the command
            stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            return output
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return ""

    def get_camera_info(self):
        """Get basic info about the camera"""
        try:
            # Connect once for all commands
            if not self.client or not self.transport:
                success, msg = self.connect()
                if not success:
                    return None, msg

            info = {}

            # Get all info in a single command to minimize round trips
            combined_cmd = (
                'echo "HOSTNAME:$(hostname)"; '
                'echo "UPTIME:$(uptime)"; '
                'echo "DISK:$(df -h / | tail -1)"; '
                'echo "MEMORY:$(free -h 2>/dev/null | grep Mem || cat /proc/meminfo | head -1)"; '
                'echo "KERNEL:$(uname -r)"'
            )

            stdin, stdout, stderr = self.client.exec_command(combined_cmd, timeout=30)
            output = stdout.read().decode('utf-8', errors='ignore')

            # Parse the output
            for line in output.strip().split('\n'):
                if line.startswith('HOSTNAME:'):
                    info['hostname'] = line[9:].strip()
                elif line.startswith('UPTIME:'):
                    info['uptime'] = line[7:].strip()
                elif line.startswith('DISK:'):
                    info['disk_usage'] = line[5:].strip()
                elif line.startswith('MEMORY:'):
                    info['memory'] = line[7:].strip()
                elif line.startswith('KERNEL:'):
                    info['kernel'] = line[7:].strip()

            if not info.get('hostname'):
                return None, "Failed to get camera info"

            return info, "Info retrieved successfully"

        except Exception as e:
            return None, f"Failed to get camera info: {str(e)}"

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
