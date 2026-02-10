from ftplib import FTP, error_perm
from interfaces import ConnectionTest
from dto import AccessResult, OSInfo
from enums import AccessLevel, AccessFailure
from session import FTPSession
import socket
import re


class FTPConnection(ConnectionTest):
    name = "FTP"

    def __init__(self, host, user=None, password=None, timeout=5):
        super().__init__(host, user, password, timeout)
        self.client = None

    def connect(self, port) -> AccessResult:
        try:
            self.client = FTP()
            self.client.connect(self.host, port, timeout=self.timeout)
            self.client.login(self.user, self.password)

            self.session = FTPSession(self.client)

            return AccessResult(
                level=AccessLevel.AUTHENTICATED
            )

        except error_perm as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.AUTH_FAILED,
                message=str(e)
            )

        except socket.timeout:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.TIMEOUT,
                message="FTP timeout (possible firewall)"
            )

        except ConnectionRefusedError:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.PORT_CLOSED,
                message="FTP port refused"
            )

        except Exception as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.UNKNOWN,
                message=str(e)
            )

    def detect_os(self, port) -> OSInfo:
        if not self.client:
            return OSInfo.unknown()

        try:
            banner = self.client.getwelcome()
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

        if "ubuntu" in banner_lower:
            os_info.os = "Linux"
            os_info.family = "Unix"
            os_info.distro = "Ubuntu"
            os_info.vendor = "Canonical"
            os_info.confidence = "high"

        elif "debian" in banner_lower:
            os_info.os = "Linux"
            os_info.family = "Unix"
            os_info.distro = "Debian"
            os_info.vendor = "Debian"
            os_info.confidence = "high"

        elif "windows" in banner_lower:
            os_info.os = "Windows"
            os_info.family = "Windows"
            os_info.vendor = "Microsoft"
            os_info.confidence = "high"

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
                self.client.quit()
            except Exception:
                pass
            finally:
                self.client = None
