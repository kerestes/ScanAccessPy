import paramiko
import socket
import re

from interfaces import ConnectionTest
from dto import AccessResult, OSInfo
from enums import AccessLevel, AccessFailure
from session import SSHSession


class SSHConnection(ConnectionTest):
    name = "SSH"

    def __init__(self, host, user=None, password=None, timeout=5):
        super().__init__(host, user, password, timeout)
        self.client = None
        self.session = None

    def connect(self, port) -> AccessResult:
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.client.connect(
                hostname=self.host,
                port=port,
                username=self.user,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )

            self.session = SSHSession(self.client)

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
                message="SSH timeout (possible firewall)"
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
        Primary: authenticated command execution
        Fallback: SSH banner
        """
        # ---------- PRIMARY: COMMAND-BASED ----------
        if self.session:
            try:
                stdin, stdout, stderr = self.session.exec_command(
                    "uname -a && cat /etc/os-release 2>/dev/null"
                )

                output = stdout.read().decode(errors="ignore").lower()

                os_info = OSInfo(
                    os="Unknown",
                    family="Unknown",
                    distro="Unknown",
                    version="Unknown",
                    kernel="Unknown",
                    architecture="Unknown",
                    vendor="Unknown",
                    device_type="Server",
                    confidence="medium",
                )

                # -------- OS / FAMILY --------
                if "linux" in output:
                    os_info.os = "Linux"
                    os_info.family = "Unix"

                elif "darwin" in output:
                    os_info.os = "macOS"
                    os_info.family = "Unix"
                    os_info.vendor = "Apple"
                    os_info.confidence = "high"
                    return os_info

                # -------- DISTRO --------
                if "ubuntu" in output:
                    os_info.distro = "Ubuntu"
                    os_info.vendor = "Canonical"
                    os_info.confidence = "high"

                elif "debian" in output:
                    os_info.distro = "Debian"
                    os_info.vendor = "Debian"
                    os_info.confidence = "high"

                elif "centos" in output:
                    os_info.distro = "CentOS"
                    os_info.vendor = "Red Hat"
                    os_info.confidence = "high"

                elif "rhel" in output or "red hat" in output:
                    os_info.distro = "RHEL"
                    os_info.vendor = "Red Hat"
                    os_info.confidence = "high"

                elif "alpine" in output:
                    os_info.distro = "Alpine"
                    os_info.vendor = "Alpine Linux"
                    os_info.confidence = "high"

                # -------- VERSION --------
                version_match = re.search(r"\b\d+(\.\d+)+\b", output)
                if version_match:
                    os_info.version = version_match.group(0)

                # -------- ARCH --------
                if "x86_64" in output or "amd64" in output:
                    os_info.architecture = "x86_64"
                elif "arm" in output:
                    os_info.architecture = "ARM"

                # -------- KERNEL --------
                kernel_match = re.search(r"linux\s+([\w\.-]+)", output)
                if kernel_match:
                    os_info.kernel = kernel_match.group(1)

                return os_info

            except Exception:
                pass

        # ---------- FALLBACK: SSH BANNER ----------
        try:
            banner = self.client.get_transport().remote_version
            banner_lower = banner.lower()

            os_info = OSInfo(
                os="Unknown",
                family="Unknown",
                distro="Unknown",
                version=banner.strip(),
                device_type="Server",
                confidence="low",
            )

            if "openssh" in banner_lower:
                os_info.family = "Unix"

            if "ubuntu" in banner_lower:
                os_info.os = "Linux"
                os_info.distro = "Ubuntu"
                os_info.vendor = "Canonical"
                os_info.confidence = "medium"

            elif "debian" in banner_lower:
                os_info.os = "Linux"
                os_info.distro = "Debian"
                os_info.vendor = "Debian"
                os_info.confidence = "medium"

            elif "freebsd" in banner_lower:
                os_info.os = "FreeBSD"
                os_info.family = "BSD"
                os_info.vendor = "FreeBSD Foundation"
                os_info.confidence = "medium"

            return os_info

        except Exception:
            return OSInfo.unknown()

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
