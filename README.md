# ScanAccessPy

ScanAccessPy is a **multi-protocol remote access auditing tool** written in Python.  
It scans remote services, attempts authenticated or unauthenticated access, and enumerates accessible filesystems in a **safe, structured, and protocol-agnostic way**.

This project is designed for **security auditing, infrastructure assessment, and learning purposes**, not for exploitation or unauthorized access.

---

## ⚠️ Disclaimer

ScanAccessPy is an auditing and educational tool.

Do NOT use this software on systems you do not own or have explicit permission to audit.

Unauthorized access to computer systems is illegal in many jurisdictions.

The author is not responsible for misuse of this tool.

Use ScanAccessPy ethically and responsibly.

## 🚀 What does ScanAccessPy do?

ScanAccessPy is a tool designed to **test remote access to a target host** using an IP address, username, and password, and to **extract as much information as possible from the established connection**.

It attempts to authenticate against common remote access services and, when access is granted, performs basic inspection and enumeration actions allowed by the protocol.

### Supported connection types

- **SSH**
- **SFTP**
- **FTP**
- **FTPS**
- **Telnet**


---

## ✨ Features

ScanAccessPy provides a set of features focused on remote access testing and information gathering:

- **Multi‑protocol remote access testing**
  - Attempts connection using IP, username, and password
  - Supports SSH, SFTP, FTP, FTPS, and Telnet

- **Port detection and service discovery**
  - Optional port scanning using **Nmap**
  - Automatically correlates open ports with supported protocols

- **Filesystem enumeration**
  - Directory and file listing starting from:
    - A user‑defined path, or
    - The highest accessible directory (root discovery)
  - Recursive traversal with configurable depth

- **Root / top‑level discovery**
  - Attempts to navigate upward in the filesystem to identify the maximum accessible directory

- **OS detection**
  - Enhanced operating system fingerprinting
  - Environment and platform hints based on filesystem structure

- **Configurable output**
  - Results can be written to an output file
  - Support format: JSON

---

## 🛣️ Planned / Future Features

The following features are planned or under consideration for future releases:

- **Advanced filtering**
  - Filter filesystem results by:
    - File name 
    - Access level
    - Directory name
    - File extension
    - Size range

 
- **Remote file interaction**
  - Read files when permitted
  - Upload and download files when supported by the protocol   

- **Search and query**
  - Keyword search across file and directory names
  - Pattern matching (regex) for paths
  - Targeted discovery of sensitive files (e.g. configs, backups, credentials)

- **Selective file operations**
  - Read specific files directly via CLI parameters
  - Write or upload files conditionally
  - Batch file downloads

- **Extended reporting**
  - Export formats such as CSV, or HTML
  - Comparison between multiple scans
  - Timeline and diff‑based analysis

- **Plugin / extension system**
  - Custom protocol handlers
  - Custom actions and checks
  - User‑defined scanning logic

---

## ⚙️ Usage

### Basic example

```bash
python main.py --ip 192.168.1.10 --username user --password pass
```

### With filesystem enumeration
```bash
python main.py --ip 192.168.1.10 --username user --password pass --output path/file.txt --depth 3
```

### Specify a starting path
```bash
python main.py --ip 192.168.1.10 --username user --password pass --path /var/www
```

### Port scanning with Nmap
```bash
python main.py --ip 192.168.1.10 --port-analyse
```

## 📄 Output

ScanAccessPy generates structured output that includes:

- Protocol used
- Port tested
- Access level
- OS information (when detectable)
- Filesystem tree (if collected)
- Execution parameters
- Output can be easily extended to JSON, text, or other formats.


## 🤝 Contributions

Contributions, refactors, and protocol extensions are welcome.
Feel free to open issues or pull requests.

## 🧪 Project Status

ScanAccessPy is under active development and experimentation.
APIs and behavior may evolve.