import sys

from config import Parameters
from connection import (
    SSHConnection,
    SFTPConnection,
    FTPConnection,
    FTPSConnection,
    TelnetConnection,
)
from output import Report, Output
from nmap import NmapRunner, NmapXMLParser


def main():
    params = Parameters()

    only_ip = params.ip and not params.username and not params.password

    if only_ip:
        print("[!] Only IP was provided.")
        print("[!] Only FTP and Telnet connections can be safely tested.")
        choice = input("Do you want to continue? (Y/N): ").strip().upper()
        if choice != "Y":
            print("Exiting program.")
            sys.exit(0)

    # -------------------------------------------------
    # 🔍 PORT SCAN
    # -------------------------------------------------
    if params.port_analyse:
        print("[*] Running Nmap SYN scan (-sS)...")
        runner = NmapRunner()
        xml_output = runner.syn_scan(ip=params.ip)
        ports = NmapXMLParser.parse(xml_output)
        open_ports = {p.port for p in ports}
        print(f"[+] Open ports detected: {sorted(open_ports)}")

        # Merge default ports with detected ports
        for proto, default_ports in params.port_map.items():
            merged = set(default_ports)
            if proto in ("SSH", "SFTP"):
                merged |= open_ports & {22, 2222}
            elif proto == "FTP":
                merged |= open_ports & {20, 21}
            elif proto == "FTPS":
                merged |= open_ports & {21, 990}
            elif proto == "TELNET":
                merged |= open_ports & {23}
            params.port_map[proto] = sorted(merged)

    # -------------------------------------------------
    # 🔗 Connections
    # -------------------------------------------------
    if only_ip:
        connections = [
            FTPConnection(params.ip),
            TelnetConnection(params.ip),
        ]
    else:
        connections = [
            SSHConnection(params.ip, params.username, params.password),
            SFTPConnection(params.ip, params.username, params.password),
            FTPConnection(params.ip, params.username, params.password),
            FTPSConnection(params.ip, params.username, params.password),
            TelnetConnection(params.ip, params.username, params.password),
        ]

    report = Report(target_ip=params.ip)

    # -------------------------------------------------
    # 🚀 RUN TESTS
    # -------------------------------------------------
    for conn in connections:
        ports = params.get_ports(conn.name)

        for port in ports:
            print(f"[*] Testing {conn.name} on port {port}...")

            result = conn.run(port)
            protocol = result["protocol"]
            access = result["access"]

            tree = None
            if access.success and conn.session and params.action in ("list_tree", "all"):
                try:
                    # Determine root for list_tree
                    if params.path:
                        root_path = params.path
                    else:
                        # Use ascend_to_root if no path is provided
                        asc_result = conn.session.action("ascend_to_root")
                        root_path = asc_result.stdout if asc_result.success else "."

                    action_result = conn.session.action(
                        "list_tree",
                        path=root_path,
                        depth=params.depth,
                    )
                    if action_result.success and action_result.raw:
                        tree = action_result.raw
                        print(f"[+] Collected file tree from {protocol}:{port} starting at {root_path}")
                except NotImplementedError:
                    pass
                except Exception as e:
                    print(f"[!] Failed to collect list_tree: {e}")

            # -----------------------------
            # Report
            # -----------------------------
            report.add_result(
                protocol=protocol,
                port=port,
                access=access,
                os_info=result.get("os"),
                list_tree=tree,
            )

            # -----------------------------
            # Console feedback
            # -----------------------------
            if access.success:
                print(f"[+] {protocol}:{port} OK | Access: {access.level.value}")
            else:
                print(f"[-] {protocol}:{port} FAILED | Reason: {access.failure.value}")

        conn.close()

    # -------------------------------------------------
    # 📄 OUTPUT
    # -------------------------------------------------
    report_data = report.to_dict()
    report_data["parameters"] = params.to_dict()
    Output(output_path=params.output_file).generate(report_data)


if __name__ == "__main__":
    main()
