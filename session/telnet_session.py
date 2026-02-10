import telnetlib3
import time
import base64
import os
from typing import List

from interfaces import Session
from dto import FileMetadata, ActionResult


class TelnetSession(Session):
    """
    Telnet session implementation.

    - Tudo é executado via shell remoto
    - list_dir / list_tree simulados via comandos Unix
    - upload/download via base64
    """

    def __init__(self, tn_client: telnetlib3.Telnet, timeout: float = 0.15):
        self.tn = tn_client
        self.timeout = timeout

    # -------------------------------------------------
    # Central dispatcher
    # -------------------------------------------------
    def action(self, action: str, **kwargs) -> ActionResult:
        try:
            action = action.lower()

            if action == "pwd":
                return ActionResult(success=True, stdout=self._exec("pwd"))

            if action == "cd":
                path = kwargs["path"]
                out = self._exec(f"cd {path} && pwd")
                if out:
                    return ActionResult(success=True, stdout=out)
                return ActionResult(success=False, stderr="cd failed")

            if action == "shell":
                cmd = kwargs["command"]
                return ActionResult(success=True, stdout=self._exec(cmd))

            if action == "list_dir":
                path = kwargs.get("path", ".")
                return ActionResult(success=True, raw=self.list_dir(path))

            if action == "list_tree":
                path = kwargs.get("path", ".")
                depth = kwargs.get("depth", 3)
                return ActionResult(success=True, raw=self.list_tree(path, depth))

            if action == "read_file":
                path = kwargs["path"]
                return ActionResult(success=True, raw=self.read_file(path))

            if action == "write_file":
                self.write_file(kwargs["local_path"], kwargs["remote_path"])
                return ActionResult(success=True)

            if action == "upload":
                self.upload(kwargs["local_path"], kwargs["remote_path"])
                return ActionResult(success=True)

            if action == "download":
                self.download(kwargs["remote_path"], kwargs["local_path"])
                return ActionResult(success=True)

            if action == "ascend_to_root":
                return self._ascend_to_root()

            raise NotImplementedError(f"Action not supported: {action}")

        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Primitive shell execution
    # -------------------------------------------------
    def _exec(self, command: str) -> str:
        self.tn.write(command.encode() + b"\n")
        time.sleep(self.timeout)
        try:
            return self.tn.read_very_eager().decode(errors="ignore").strip()
        except Exception:
            return ""

    # -------------------------------------------------
    # Ascend to root directory accessible
    # -------------------------------------------------
    def _ascend_to_root(self) -> ActionResult:
        try:
            original = self._exec("pwd")
            current = original

            while True:
                parent = self._exec("cd .. && pwd")
                if parent == current or not parent:
                    break
                current = parent

            # Retorna ao diretório original
            self._exec(f"cd {original}")
            return ActionResult(success=True, stdout=current)
        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # File operations via Base64
    # -------------------------------------------------
    def write_file(self, local_path: str, remote_path: str):
        if not remote_path:
            remote_path = os.path.basename(local_path)
        with open(local_path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        self._exec(f"echo '{data}' | base64 -d > {remote_path}")

    def read_file(self, path: str) -> bytes:
        out = self._exec(f"base64 {path}")
        try:
            return base64.b64decode(out)
        except Exception:
            return out.encode()

    # -------------------------------------------------
    # Directory listing / tree
    # -------------------------------------------------
    def list_dir(self, path: str) -> List[FileMetadata]:
        result: List[FileMetadata] = []
        out = self._exec(f"ls -1 {path}")
        for name in out.splitlines():
            full = f"{path}/{name}".replace("//", "/")
            meta = self._stat_path(full)
            if meta:
                result.append(meta)
        return result

    def list_tree(self, path: str = ".", depth: int = 3) -> List[FileMetadata]:
        if depth <= 0:
            return []
        result: List[FileMetadata] = []
        for entry in self.list_dir(path):
            result.append(entry)
            if entry.is_dir:
                result.extend(self.list_tree(entry.path, depth - 1))
        return result

    def _stat_path(self, path: str) -> FileMetadata | None:
        out = self._exec(f"stat -c '%F|%s|%a|%U|%G|%Y' {path} 2>/dev/null")
        if not out or "|" not in out:
            return None
        ftype, size, perms, owner, group, mtime = out.split("|")
        return FileMetadata(
            path=path,
            is_dir="directory" in ftype.lower(),
            size=int(size),
            permissions=perms,
            owner=owner,
            group=group,
            modified_time=mtime,
        )

    # -------------------------------------------------
    # Transfer aliases
    # -------------------------------------------------
    def upload(self, local_path: str, remote_path: str):
        self.write_file(local_path, remote_path)

    def download(self, remote_path: str, local_path: str):
        data = self.read_file(remote_path)
        with open(local_path, "wb") as f:
            f.write(data)

    # -------------------------------------------------
    # Lifecycle
    # -------------------------------------------------
    def close(self):
        if self.tn:
            try:
                self.tn.write(b"exit\n")
            except Exception:
                pass
            finally:
                self.tn.close()
                self.tn = None
