from datetime import datetime
from typing import Dict, Optional
import json


class Output:
    """
    Handles program output.
    If output_path is None -> print to stdout
    Otherwise -> write formatted report to file
    """

    def __init__(self, output_path: Optional[str] = None):
        self.output_path = output_path

    # ------------------------------
    # Public
    # ------------------------------

    def generate(self, data: Dict):
        """
        Generate human-readable report output.
        """
        report = self._format_text(data)

        if self.output_path:
            self._write_file(report)
        else:
            print(report)

    def generate_json(self, data: Dict):
        """
        Optional: structured JSON output
        """
        content = json.dumps(data, indent=2, default=str)
        if self.output_path:
            self._write_file(content)
        else:
            print(content)

    # ------------------------------
    # Internal helpers
    # ------------------------------

    def _write_file(self, content: str):
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def _format_text(self, data: Dict) -> str:
        """
        Human-readable report format.
        """
        lines = []
        lines.append("=" * 70)
        lines.append("Connection Analysis Report")
        lines.append("=" * 70)
        lines.append(f"Target IP    : {data.get('target', 'Unknown')}")
        lines.append(f"Generated at : {datetime.utcnow().isoformat()} UTC")
        lines.append("")

        # ------------------------------
        # Parameters
        # ------------------------------
        if data.get("parameters"):
            lines.append("[Parameters]")
            for k, v in data["parameters"].items():
                lines.append(f"- {k}: {v}")
            lines.append("")

        # ------------------------------
        # Nmap results
        # ------------------------------
        if "nmap" in data:
            lines.append("[Nmap Scan]")
            open_ports = data["nmap"].get("open_ports", [])
            lines.append(
                f"Open ports: {', '.join(map(str, open_ports)) or 'None'}"
            )
            lines.append("")

        # ------------------------------
        # Connection results
        # ------------------------------
        lines.append("[Connection Results]")
        for r in data.get("results", []):
            proto = r.get("protocol")
            port = r.get("port")
            access = r.get("access_level")

            if access != "NO_ACCESS":
                lines.append(
                    f"[+] {proto.upper()}:{port} | Access: {access}"
                )
            else:
                lines.append(
                    f"[-] {proto.upper()}:{port} | Reason: {r.get('failure', 'unknown')}"
                )
        lines.append("")

        # ------------------------------
        # File tree per protocol
        # ------------------------------
        list_tree = data.get("list_tree")
        if list_tree:
            lines.append("[File / Directory Structure]")

            for proto, entries in list_tree.items():
                lines.append(f"\n[{proto.upper()}]")

                if not entries:
                    lines.append("  (no entries)")
                    continue

                for meta in entries:
                    type_flag = "DIR " if meta["is_dir"] else "FILE"
                    lines.append(
                        f"  - [{type_flag}] {meta['path']}"
                    )
                    lines.append(
                        f"      size={meta['size']} "
                        f"perm={meta['permissions']} "
                        f"owner={meta['owner']} "
                        f"group={meta['group']} "
                        f"modified={meta['modified_time']}"
                    )

            lines.append("")

        # ------------------------------
        # OS detection
        # ------------------------------
        if data.get("os_detect"):
            osd = data["os_detect"]
            lines.append("[OS Detection]")
            lines.append(f"- OS        : {osd.get('os', 'Unknown')}")
            lines.append(f"- Family    : {osd.get('family', 'Unknown')}")
            lines.append(f"- Distro    : {osd.get('distro', 'Unknown')}")
            lines.append(f"- Version   : {osd.get('version', 'Unknown')}")
            lines.append(f"- Arch      : {osd.get('architecture', 'Unknown')}")
            lines.append(f"- Kernel    : {osd.get('kernel', 'Unknown')}")
            lines.append(f"- Vendor    : {osd.get('vendor', 'Unknown')}")
            lines.append(f"- Device    : {osd.get('device_type', 'Unknown')}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)
