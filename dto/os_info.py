class OSInfo:
    """
    Generic Operating System fingerprinting result.
    Designed to support Unix, Linux, BSD, macOS, Windows,
    Network OS and Embedded systems.
    """

    def __init__(
        self,
        os: str = "Unknown",
        family: str = "Unknown",
        distro: str = "Unknown",
        version: str = "Unknown",
        kernel: str = "Unknown",
        architecture: str = "Unknown",
        vendor: str = "Unknown",
        device_type: str = "Unknown",
        confidence: str = "low"
    ):
        self.os = os                # Linux, Windows, BSD, macOS, IOS, etc
        self.family = family        # Unix, Windows, NetworkOS, Embedded
        self.distro = distro        # Ubuntu, FreeBSD, OpenBSD, RouterOS
        self.version = version      # 20.04, 13.2, 10.0.19045
        self.kernel = kernel        # 5.15.0-89-generic
        self.architecture = architecture  # x86_64, armv7, aarch64
        self.vendor = vendor        # Canonical, Apple, Microsoft, Cisco
        self.device_type = device_type  # Server, Desktop, Router, Switch
        self.confidence = confidence  # low | medium | high

    @classmethod
    def unknown(cls):
        return cls()

    def to_dict(self):
        return {
            "os": self.os,
            "family": self.family,
            "distro": self.distro,
            "version": self.version,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "confidence": self.confidence
        }

    def __str__(self):
        return (
            f"{self.os} {self.distro} {self.version} "
            f"({self.architecture}) "
            f"[{self.confidence}]"
        )
