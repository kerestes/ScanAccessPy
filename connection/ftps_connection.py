from ftplib import FTP_TLS, error_perm
import socket
import re

from interfaces import ConnectionTest
from dto import AccessResult, OSInfo
from enums import AccessLevel, AccessFailure
from session import FTPSSession


class FTPSConnection(ConnectionTest):
    name = "FTPS"

    def __init__(self, host, user=None, password=None, timeout=5):
        super().__init__(host, user, password, timeout)
        self.client = None
        self.session = None

    # --------------------------------------------------
    # Connection
    # --------------------------------------------------

    def connect(self, port) -> AccessResult:
        try:
            self.client = FTP_TLS(timeout=self.timeout)
            self.client.connect(self.host, port)
            self.client.login(self.user, self.password)

            # Secure data channel (explicit FTPS)
            self.client.prot_p()

            self.session = FTPSSession(self.client)

            return AccessResult(
                level=AccessLevel.AUTHENTICATED
            )

        except error_perm as e:
            self.close()
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.AUTH_FAILED,
                message=str(e)
            )

        except socket.timeout:
            self.close()
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.TIMEOUT,
                message="FTPS timeout (possible firewall or TLS issue)"
            )

        except ConnectionRefusedError:
            self.close()
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.PORT_CLOSED,
                message="FTPS port refused"
            )

        except Exception as e:
            self.close()
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.UNKNOWN,
                message=str(e)
            )

    # --------------------------------------------------
    # OS detection (banner-based)
    # --------------------------------------------------

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
            vendor="Unknown",
            device_type="Server",
            confidence="low",
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

            elif "red hat" in banner_lower or "rhel" in banner_lower:
                os_info.distro = "RHEL"
                os_info.vendor = "Red Hat"
                os_info.confidence = "high"

        # -------- BSD --------
        elif "freebsd" in banner_lower:
            os_info.os = "FreeBSD"
            os_info.family = "BSD"
            os_info.vendor = "FreeBSD Foundation"
            os_info.confidence = "high"

        elif "openbsd" in banner_lower:
            os_info.os = "OpenBSD"
            os_info.family = "BSD"
            os_info.vendor = "OpenBSD Project"
            os_info.confidence = "high"

        elif "netbsd" in banner_lower:
            os_info.os = "NetBSD"
            os_info.family = "BSD"
            os_info.vendor = "NetBSD Foundation"
            os_info.confidence = "high"

        # -------- WINDOWS --------
        elif "windows" in banner_lower or "microsoft" in banner_lower:
            os_info.os = "Windows"
            os_info.family = "Windows"
            os_info.vendor = "Microsoft"
            os_info.confidence = "high"

        # -------- NETWORK / EMBEDDED --------
        elif "routeros" in banner_lower:
            os_info.os = "RouterOS"
            os_info.family = "NetworkOS"
            os_info.distro = "MikroTik RouterOS"
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
        version_match = re.search(r"\b\d+(\.\d+)+\b", banner)
        if version_match:
            os_info.version = version_match.group(0)

        return os_info

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

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
