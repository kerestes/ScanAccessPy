import argparse
from typing import List, Optional, Dict


class Parameters:
    """
    CLI parameter parser and execution context.
    Provides a clean interface between argparse and the core logic.
    """

    # ----------------------------
    # Defaults
    # ----------------------------

    DEFAULT_PORT_MAP = {
        "SSH": [22],
        "SFTP": [22],
        "FTP": [21, 20],
        "FTPS": [21, 990],
        "TELNET": [23],
    }

    # ----------------------------
    # Init
    # ----------------------------

    def __init__(self):
        self.port_map = self.DEFAULT_PORT_MAP.copy()

        self.parser = argparse.ArgumentParser(
            description="Remote access and protocol analysis tool"
        )

        self._register_arguments()
        self.args = self.parser.parse_args()

        # Normalize / expose stable attributes
        self._normalize()

    # ----------------------------
    # Argument registration
    # ----------------------------

    def _register_arguments(self):
        self.parser.add_argument(
            "--ip",
            required=True,
            help="Target IP address"
        )

        self.parser.add_argument(
            "--username",
            default=None,
            help="Username for authentication"
        )

        self.parser.add_argument(
            "--password",
            default=None,
            help="Password for authentication"
        )

        self.parser.add_argument(
            "--connection",
            default="all",
            choices=["ssh", "sftp", "ftp", "ftps", "telnet", "all"],
            help="Protocol to test (default: all)"
        )

        self.parser.add_argument(
            "--depth",
            type=int,
            default=3,
            help="Depth of directory tree to list (default: 1)"
        )

        self.parser.add_argument(
            "--action",
            default="all",
            choices=["read_file", "write", "read_dir", "all"],
            help="Action to perform (default: all)"
        )

        self.parser.add_argument(
            "--script",
            default=None,
            help="Local script/file to upload"
        )

        self.parser.add_argument(
            "--path",
            default=None,
            help="Remote path (default: .)"
        )

        self.parser.add_argument(
            "--os",
            nargs="+",
            default=["all"],
            choices=["linux", "win", "bsd", "macos", "all"],
            help="Target OS (default: all)"
        )

        self.parser.add_argument(
            "--port",
            type=int,
            action="append",
            help="Explicit port(s) to test (overrides defaults)"
        )

        # Nmap
        self.parser.add_argument(
            "--port-analyse",
            dest="port_analyse",
            action="store_true",
            default=True,
            help="Enable nmap port scan (default)"
        )

        self.parser.add_argument(
            "--no-port-analyse",
            dest="port_analyse",
            action="store_false",
            help="Disable nmap port scan"
        )

        # Output
        self.parser.add_argument(
            "--output",
            dest="output_file",
            default=None,
            help="Output file path (if omitted, print to stdout)"
        )

    # ----------------------------
    # Normalization
    # ----------------------------

    def _normalize(self):
        """
        Normalize and expose argparse values as stable attributes.
        Prevents AttributeError and keeps main.py clean.
        """
        self.ip: str = self.args.ip
        self.username: Optional[str] = self.args.username
        self.password: Optional[str] = self.args.password
        self.connection: str = self.args.connection.upper()
        self.action: str = self.args.action
        self.script: Optional[str] = self.args.script
        self.path: str = self.args.path
        self.os_list: List[str] = self.args.os
        self.port_analyse: bool = self.args.port_analyse
        self.output_file: Optional[str] = self.args.output_file
        self.explicit_ports: Optional[List[int]] = self.args.port
        self.depth: int = self.args.depth

    # ----------------------------
    # Port resolution
    # ----------------------------

    def get_ports(self, protocol_name: str) -> List[int]:
        """
        Resolve ports for a protocol.

        Priority:
        1. --port argument (global override)
        2. Protocol default ports
        """
        if self.explicit_ports:
            return sorted(set(self.explicit_ports))

        return self.port_map.get(protocol_name.upper(), [])

    # ----------------------------
    # Export (for Report / Output)
    # ----------------------------

    def to_dict(self) -> Dict:
        """
        Export parameters for report/output.
        """
        return {
            "ip": self.ip,
            "username": self.username,
            "connection": self.connection,
            "action": self.action,
            "path": self.path,
            "os": self.os_list,
            "port_analyse": self.port_analyse,
            "explicit_ports": self.explicit_ports,
            "output_file": self.output_file,
        }
