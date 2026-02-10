import subprocess
import shutil


class NmapRunner:
    """
    Executes Nmap scans using system nmap binary.
    Designed for heavy / effective scans (SYN scan).
    """

    def __init__(self, binary: str = "nmap"):
        self.binary = shutil.which(binary)
        if not self.binary:
            raise RuntimeError("nmap binary not found in PATH")

    def syn_scan(
        self,
        ip: str,
        ports: str = "-",
        min_rate: int = 5000,
        max_retries: int = 2,
        timing: str = "T4"
    ) -> str:
        """
        Run SYN scan (-sS) and return XML output as string.
        Requires elevated privileges.
        """

        cmd = [
            self.binary,
            "-sS",                  # SYN scan
            "-Pn",                  # no ping
            "-n",                   # no DNS
            f"-p{ports}",           # port range
            "--open",
            "--min-rate", str(min_rate),
            "--max-retries", str(max_retries),
            f"-{timing}",
            "-oX", "-",             # XML to stdout
            ip
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Nmap failed: {result.stderr.strip()}"
            )

        return result.stdout
