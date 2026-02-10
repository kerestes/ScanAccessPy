import paramiko
import socket
import re

from interfaces import ConnectionTest
from dto import AccessResult, OSInfo
from enums import AccessLevel, AccessFailure
from session import SFTPSession


class SFTPConnection(ConnectionTest):
    name = "SFTP"

    def __init__(self, host, user=None, password=None, timeout=5):
        super().__init__(host, user, password, timeout)
        self.transport = None
        self.client = None
        self.session = None

    def connect(self, port) -> AccessResult:
        try:
            self.transport = paramiko.Transport((self.host, port))
            self.transport.banner_timeout = self.timeout
            self.transport.auth_timeout = self.timeout

            self.transport.connect(
                username=self.user,
                password=self.password
            )

            self.client = paramiko.SFTPClient.from_transport(self.transport)
            self.session = SFTPSession(self.client)

            return AccessResult(
                level=AccessLevel.AUTHENTICATED
            )

        except paramiko.AuthenticationException as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.AUTH_FAILED,
                message=str(e)
            )

        except socket.timeout:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.TIMEOUT,
                message="SSH/SFTP timeout"
            )

        except paramiko.SSHException as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.PROTOCOL_ERROR,
                message=str(e)
            )

        except OSError as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.HOST_UNREACHABLE,
                message=str(e)
            )

        except Exception as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.UNKNOWN,
                message=str(e)
            )

    def detect_os(self, port) -> OSInfo:
        """
        SFTP roda sobre SSH.
        Fingerprinting via banner SSH (remote_version).
        """
        if not self.transport:
            return OSInfo.unknown()

        try:
            banner = self.transport.remote_version
            banner_lower = banner.lower()
        except Exception:
            return OSInfo.unknown()

        os_info = OSInfo(
            os="Unknown",
            family="Unknown",
            distro="Unknown",
            version=banner.strip(),
            device_type="Server",
            confidence="low"
        )

        # -------- LINUX --------
        if "linux" in banner_lower:
            os_info.os = "Linux"
            os_info.family = "Unix"
            os_info.confidence = "medium"

            if "ubuntu" in banner_lower:
                os_info.distro = "Ubuntu"
                os_info.vendor = "Canonical"
                os_info.confidence = "high"

            elif "debian" in banner_lower:
                os_info.distro = "Debian"
                os_info.vendor = "Debian"
                os_info.confidence = "high"

            elif "centos" in banner_lower:
                os_info.distro = "CentOS"
                os_info.vendor = "Red Hat"
                os_info.confidence = "high"

            elif "rhel" in banner_lower or "red hat" in banner_lower:
                os_info.distro = "RHEL"
                os_info.vendor = "Red Hat"
                os_info.confidence = "high"

        # -------- BSD --------
        elif "freebsd" in banner_lower:
            os_info.os = "FreeBSD"
            os_info.family = "BSD"
            os_info.distro = "FreeBSD"
            os_info.vendor = "FreeBSD Foundation"
            os_info.confidence = "high"

        elif "openbsd" in banner_lower:
            os_info.os = "OpenBSD"
            os_info.family = "BSD"
            os_info.distro = "OpenBSD"
            os_info.vendor = "OpenBSD Project"
            os_info.confidence = "high"

        # -------- MACOS --------
        elif "darwin" in banner_lower or "macos" in banner_lower:
            os_info.os = "macOS"
            os_info.family = "Unix"
            os_info.vendor = "Apple"
            os_info.confidence = "high"

        # -------- NETWORK / EMBEDDED --------
        elif "routeros" in banner_lower:
            os_info.os = "RouterOS"
            os_info.family = "NetworkOS"
            os_info.vendor = "MikroTik"
            os_info.device_type = "Router"
            os_info.confidence = "high"

        elif "openwrt" in banner_lower:
            os_info.os = "Linux"
            os_info.family = "Embedded"
            os_info.distro = "OpenWrt"
            os_info.vendor = "OpenWrt"
            os_info.device_type = "Router"
            os_info.confidence = "high"

        # -------- VERSION EXTRACTION --------
        match = re.search(r"\b\d+(\.\d+)+\b", banner)
        if match:
            os_info.version = match.group(0)

        return os_info

    def close(self):
        if self.session:
            self.session.close()
            self.session = None

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            finally:
                self.client = None

        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass
            finally:
                self.transport = None
