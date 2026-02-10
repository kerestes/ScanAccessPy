from collections import defaultdict
from typing import List, Optional
from dto import OSInfo, AccessResult, FileMetadata


class Report:
    """
    Consolidates and analyzes connection results from multiple protocols.
    Produces a structured dictionary suitable for Output.
    """

    def __init__(self, target_ip: str):
        self.target_ip = target_ip

        # protocol -> list[connection results]
        self.data: defaultdict[str, List[dict]] = defaultdict(list)

        # protocol -> OSInfo (best confidence per protocol)
        self.os_info: dict[str, OSInfo] = {}

        # protocol -> list[FileMetadata]
        self.list_tree: defaultdict[str, List[FileMetadata]] = defaultdict(list)

    # -------------------------------------------------
    # Add results from a single protocol/port
    # -------------------------------------------------
    def add_result(
        self,
        protocol: str,
        port: int,
        access: AccessResult,
        os_info: Optional[OSInfo] = None,
        list_tree: Optional[List[FileMetadata]] = None,
    ):
        """
        Add a single connection result.
        """
        entry = {
            "protocol": protocol,
            "port": port,
            "access_level": access.level.value,
            "failure": access.failure.value,
            "message": access.message,
        }
        self.data[protocol].append(entry)

        # OS info per protocol (keep highest confidence)
        if os_info:
            existing = self.os_info.get(protocol)
            if (
                not existing
                or self._confidence_value(os_info.confidence)
                > self._confidence_value(existing.confidence)
            ):
                self.os_info[protocol] = os_info

        # File tree per protocol (ensure list)
        if list_tree and isinstance(list_tree, list):
            self.list_tree[protocol].extend(list_tree)

    # -------------------------------------------------
    # Internal helper
    # -------------------------------------------------
    @staticmethod
    def _confidence_value(conf: str) -> int:
        return {"low": 0, "medium": 1, "high": 2}.get(conf.lower(), 0)

    # -------------------------------------------------
    # Generate dictionary for output
    # -------------------------------------------------
    def to_dict(self) -> dict:
        """
        Produce a unified dictionary for Output.
        """
        result = {
            "target": self.target_ip,
            "results": [],
            "os_info": {},
            "list_tree": {k: [fmeta.__dict__ for fmeta in v] for k, v in self.list_tree.items()} if self.list_tree else None,
            "os_detect": None,
        }

        # Flatten connection results
        for entries in self.data.values():
            result["results"].extend(entries)

        # OS info per protocol
        for proto, osinfo in self.os_info.items():
            result["os_info"][proto] = osinfo.to_dict()

        # Consolidated OS detection (highest confidence overall)
        if self.os_info:
            best_os = max(
                self.os_info.values(),
                key=lambda o: self._confidence_value(o.confidence),
            )
            result["os_detect"] = best_os.to_dict()

        return result

    # -------------------------------------------------
    # Optional human-readable summary
    # -------------------------------------------------
    def summary_text(self) -> str:
        lines = [
            f"Report for {self.target_ip}",
            "=" * 60,
        ]

        for proto, entries in self.data.items():
            lines.append(f"[{proto}]")

            # Connection results
            for entry in entries:
                status = "SUCCESS" if entry["access_level"] != "NO_ACCESS" else "FAILED"
                lines.append(
                    f"- Port {entry['port']}: {status} | "
                    f"Access: {entry['access_level']} | "
                    f"Reason: {entry['failure']}"
                )

            # OS info per protocol
            osinfo = self.os_info.get(proto)
            if osinfo:
                lines.append(
                    f"  OS Info: {osinfo.os} {osinfo.distro} "
                    f"{osinfo.version} | Confidence: {osinfo.confidence}"
                )

            # File tree per protocol
            tree = self.list_tree.get(proto)
            if tree:
                lines.append(f"  File/Directory Structure for {proto}:")
                for fmeta in tree:
                    is_dir = "DIR" if fmeta.is_dir else "FILE"
                    lines.append(
                        f"    - [{is_dir}] {fmeta.path} "
                        f"(size={fmeta.size}, perm={fmeta.permissions}, "
                        f"owner={fmeta.owner}, group={fmeta.group}, "
                        f"modified={fmeta.modified_time})"
                    )

        # Consolidated OS
        if self.os_info:
            best_os = max(
                self.os_info.values(),
                key=lambda o: self._confidence_value(o.confidence),
            )
            lines.append("\n[Consolidated OS Detection]")
            lines.append(
                f"{best_os.os} {best_os.distro} "
                f"{best_os.version} | Confidence: {best_os.confidence}"
            )

        lines.append("=" * 60)
        return "\n".join(lines)
