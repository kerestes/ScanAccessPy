import paramiko
import stat
import os
from typing import List

from interfaces import Session
from dto import FileMetadata, ActionResult


class SSHSession(Session):
    """
    SSH Session implementation over Paramiko SSHClient.

    - Suporta shell remoto
    - Suporta operações de arquivo via SFTP
    - Todas as ações passam por action()
    """

    def __init__(self, ssh_client: paramiko.SSHClient):
        self.client = ssh_client
        self.sftp = self.client.open_sftp()

    # -------------------------------------------------
    # Central dispatcher
    # -------------------------------------------------
    def action(self, action: str, **kwargs) -> ActionResult:
        try:
            action = action.lower()

            if action == "pwd":
                return ActionResult(success=True, stdout=self.sftp.getcwd())

            if action == "cd":
                path = kwargs["path"]
                self.sftp.chdir(path)
                return ActionResult(success=True)

            if action == "list_dir":
                path = kwargs.get("path", ".")
                entries = self.list_dir(path)
                return ActionResult(success=True, raw=entries)

            if action == "list_tree":
                path = kwargs.get("path", ".")
                depth = kwargs.get("depth", 3)
                tree = self.list_tree(path, depth)
                return ActionResult(success=True, raw=tree)

            if action == "stat":
                path = kwargs["path"]
                info = self.sftp.stat(path)
                return ActionResult(success=True, raw=info)

            if action == "read_file":
                path = kwargs["path"]
                data = self.read_file(path)
                return ActionResult(success=True, raw=data)

            if action == "write_file":
                self.write_file(kwargs["local_path"], kwargs["remote_path"])
                return ActionResult(success=True)

            if action == "upload":
                self.upload(kwargs["local_path"], kwargs["remote_path"])
                return ActionResult(success=True)

            if action == "download":
                self.download(kwargs["remote_path"], kwargs["local_path"])
                return ActionResult(success=True)

            if action == "shell":
                cmd = kwargs["command"]
                return self.run_shell(cmd)

            if action == "ascend_to_root":
                return self._ascend_to_root()

            raise NotImplementedError(f"Action not supported: {action}")

        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Ascend to root directory accessible by the user
    # -------------------------------------------------
    def _ascend_to_root(self) -> ActionResult:
        try:
            original = self.sftp.getcwd()
            current = original

            while True:
                try:
                    self.sftp.chdir("..")
                    parent = self.sftp.getcwd()
                    if parent == current:
                        break  # Chegamos ao topo
                    current = parent
                except IOError:
                    break  # Não é possível subir mais

            # Retorna ao diretório original
            try:
                self.sftp.chdir(original)
            except IOError:
                pass

            return ActionResult(success=True, stdout=current)
        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Shell execution
    # -------------------------------------------------
    def run_shell(self, command: str) -> ActionResult:
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            return ActionResult(
                success=True,
                stdout=stdout.read().decode(errors="ignore"),
                stderr=stderr.read().decode(errors="ignore"),
            )
        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Primitive file operations
    # -------------------------------------------------
    def write_file(self, local_path: str, remote_path: str):
        if not remote_path:
            remote_path = os.path.basename(local_path)
        self.sftp.put(local_path, remote_path)

    def read_file(self, path: str) -> bytes:
        with self.sftp.file(path, "rb") as f:
            return f.read()

    def list_dir(self, path: str) -> List[FileMetadata]:
        result: List[FileMetadata] = []
        try:
            for entry in self.sftp.listdir_attr(path):
                result.append(
                    FileMetadata(
                        path=f"{path}/{entry.filename}".replace("//", "/"),
                        is_dir=stat.S_ISDIR(entry.st_mode),
                        size=entry.st_size,
                        permissions=oct(entry.st_mode)[-3:],
                        owner=str(entry.st_uid),
                        group=str(entry.st_gid),
                        modified_time=entry.st_mtime,
                    )
                )
        except IOError:
            pass
        return result

    # -------------------------------------------------
    # Recursive tree
    # -------------------------------------------------
    def list_tree(self, path: str = ".", depth: int = 3) -> List[FileMetadata]:
        if depth <= 0:
            return []

        result: List[FileMetadata] = []
        for entry in self.list_dir(path):
            result.append(entry)
            if entry.is_dir:
                result.extend(self.list_tree(entry.path, depth - 1))
        return result

    # -------------------------------------------------
    # Transfer aliases
    # -------------------------------------------------
    def upload(self, local_path: str, remote_path: str):
        self.write_file(local_path, remote_path)

    def download(self, remote_path: str, local_path: str):
        self.sftp.get(remote_path, local_path)

    # -------------------------------------------------
    # Lifecycle
    # -------------------------------------------------
    def close(self):
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        if self.client:
            self.client.close()
            self.client = None
