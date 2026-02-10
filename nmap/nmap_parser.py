import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]


class NmapXMLParser:
    """
    Parse Nmap XML output and extract open ports and services.
    """

    @staticmethod
    def parse(xml_output: str) -> List[NmapPort]:
        root = ET.fromstring(xml_output)
        results: List[NmapPort] = []

        for port in root.findall(".//port"):
            state = port.find("state").attrib.get("state")
            if state != "open":
                continue

            service = port.find("service")

            results.append(
                NmapPort(
                    port=int(port.attrib["portid"]),
                    protocol=port.attrib["protocol"],
                    state=state,
                    service=service.attrib.get("name") if service is not None else None,
                    product=service.attrib.get("product") if service is not None else None,
                    version=service.attrib.get("version") if service is not None else None,
                )
            )

        return results

    @staticmethod
    def group_by_service(ports: List[NmapPort]) -> Dict[str, List[int]]:
        """
        Returns:
        {
            "ssh": [22, 2222],
            "ftp": [21, 2121]
        }
        """
        grouped: Dict[str, List[int]] = {}

        for p in ports:
            if not p.service:
                continue
            grouped.setdefault(p.service, []).append(p.port)

        return grouped
