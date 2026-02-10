import asyncio
import re
import telnetlib3

from interfaces import ConnectionTest
from dto import OSInfo, AccessResult
from enums import AccessLevel, AccessFailure
from session import TelnetSession


class TelnetConnection(ConnectionTest):
    name = "TELNET"

    def __init__(self, host, user=None, password=None, timeout=5):
        super().__init__(host, user, password, timeout)
        self.reader = None
        self.writer = None
        self.session = None
        self.loop = None

    # --------------------------------------------------
    # Internal async connect
    # --------------------------------------------------

    async def _async_connect(self, port):
        return await telnetlib3.open_connection(
            host=self.host,
            port=port,
            connect_minwait=self.timeout,
            connect_maxwait=self.timeout,
            shell=None,
        )

    async def _async_login(self):
        """
        Best-effort authentication (depends on remote prompts).
        """
        if not self.user:
            return

        await self.writer.write(self.user + "\n")
        await self.writer.drain()

        if self.password:
            await asyncio.sleep(0.2)
            await self.writer.write(self.password + "\n")
            await self.writer.drain()

    # --------------------------------------------------
    # Public API (sync)
    # --------------------------------------------------

    def connect(self, port) -> AccessResult:
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            self.reader, self.writer = self.loop.run_until_complete(
                self._async_connect(port)
            )

            # optional authentication
            self.loop.run_until_complete(self._async_login())

            self.session = TelnetSession(
                reader=self.reader,
                writer=self.writer,
                timeout=self.timeout,
            )

            return AccessResult(
                level=AccessLevel.USER
            )

        except asyncio.TimeoutError:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.TIMEOUT,
                message="Telnet timeout (possible firewall)"
            )

        except ConnectionRefusedError:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.PORT_CLOSED,
                message="Telnet port refused"
            )

        except Exception as e:
            return AccessResult(
                level=AccessLevel.NONE,
                failure=AccessFailure.UNKNOWN,
                message=str(e)
            )

    # --------------------------------------------------
    # OS detection (unchanged logic, new backend)
    # --------------------------------------------------

    def detect_os(self, port) -> OSInfo:
        if not self.session:
            return OSInfo.unknown()

        # ---------- PRIMARY: COMMAND EXEC ----------
        try:
            output = self.session.exec_command(
                "uname -a 2>/dev/null || cat /etc/os-release 2>/dev/null || ver"
            )

            text = output.decode(errors="ignore").lower()

            os_info = OSInfo(
                os="Unknown",
                family="Unknown",
                distro="Unknown",
                version="Unknown",
                kernel="Unknown",
                architecture="Unknown",
                vendor="Unknown",
                device_type="Embedded",
                confidence="medium",
            )

            if "linux" in text:
                os_info.os = "Linux"
                os_info.family = "Unix"

                if "ubuntu" in text:
                    os_info.distro = "Ubuntu"
                    os_info.vendor = "Canonical"
                    os_info.confidence = "high"

                elif "debian" in text:
                    os_info.distro = "Debian"
                    os_info.vendor = "Debian"
                    os_info.confidence = "high"

                elif "busybox" in text:
                    os_info.distro = "BusyBox"
                    os_info.device_type = "Embedded"
                    os_info.confidence = "high"

            elif "freebsd" in text:
                os_info.os = "FreeBSD"
                os_info.family = "BSD"
                os_info.vendor = "FreeBSD Foundation"
                os_info.confidence = "high"

            elif "windows" in text or "microsoft" in text:
                os_info.os = "Windows"
                os_info.family = "Windows"
                os_info.device_type = "Server"
                os_info.confidence = "medium"

            version_match = re.search(r"\b\d+(\.\d+)+\b", text)
            if version_match:
                os_info.version = version_match.group(0)

            if "x86_64" in text or "amd64" in text:
                os_info.architecture = "x86_64"
            elif "arm" in text:
                os_info.architecture = "ARM"

            return os_info

        except Exception:
            pass

        # ---------- FALLBACK: BANNER ----------
        try:
            banner = self.session.exec_command("\n").decode(errors="ignore").lower()

            os_info = OSInfo(
                os="Unknown",
                family="Unknown",
                distro="Unknown",
                version=banner.strip(),
                device_type="Embedded",
                confidence="low",
            )

            if "busybox" in banner:
                os_info.os = "Linux"
                os_info.distro = "BusyBox"
                os_info.confidence = "medium"

            elif "cisco" in banner:
                os_info.os = "Cisco IOS"
                os_info.vendor = "Cisco"
                os_info.device_type = "NetworkDevice"
                os_info.confidence = "high"

            elif "mikrotik" in banner:
                os_info.os = "RouterOS"
                os_info.vendor = "MikroTik"
                os_info.device_type = "NetworkDevice"
                os_info.confidence = "high"

            return os_info

        except Exception:
            return OSInfo.unknown()

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

    def close(self):
        if self.session:
            self.session.close()
            self.session = None

        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
            finally:
                self.writer = None

        if self.loop:
            try:
                self.loop.close()
            except Exception:
                pass
            finally:
                self.loop = None
