from ftplib import FTP, error_perm
from interfaces import Session
from dto import FileMetadata, ActionResult
from typing import List
import os


class FTPSSession(Session):
    """
    FTPS Session implementation using Python's ftplib.

    - NÃO suporta shell / exec
    - Todas as operações passam por action()
    """

    def __init__(self, ftp_client: FTP):
        self.client = ftp_client

    # -------------------------------------------------
    # Central dispatcher
    # -------------------------------------------------
    def action(self, action: str, **kwargs) -> ActionResult:
        try:
            action = action.lower()

            if action == "pwd":
                return ActionResult(success=True, stdout=self.client.pwd())

            if action == "cd":
                path = kwargs["path"]
                self.client.cwd(path)
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

            if action == "ascend_to_root":
                return self._ascend_to_root()

            raise NotImplementedError(f"Action not supported: {action}")

        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Ascend to top directory accessible by the user
    # -------------------------------------------------
    def _ascend_to_root(self) -> ActionResult:
        """
        Move recursively to the top-most directory the user can access.
        Returns the path of that directory and leaves the session
        in the original directory.
        """
        try:
            original = self.client.pwd()
            current = original

            while True:
                try:
                    self.client.cwd("..")
                    parent = self.client.pwd()
                    if parent == current:
                        break  # Reached top-most accessible directory
                    current = parent
                except error_perm:
                    break  # Cannot go up further

            # Return to original directory
            try:
                self.client.cwd(original)
            except error_perm:
                pass

            return ActionResult(success=True, stdout=current)
        except Exception as e:
            return ActionResult(success=False, stderr=str(e))

    # -------------------------------------------------
    # Primitive file operations
    # -------------------------------------------------
    def write_file(self, local_path: str, remote_path: str):
        if not remote_path:
            remote_path = os.path.basename(local_path)
        with open(local_path, "rb") as f:
            self.client.storbinary(f"STOR {remote_path}", f)

    def read_file(self, path: str) -> bytes:
        chunks: List[bytes] = []

        def _collector(chunk: bytes):
            chunks.append(chunk)

        self.client.retrbinary(f"RETR {path}", _collector)
        return b"".join(chunks)

    def list_dir(self, path: str) -> List[FileMetadata]:
        result: List[FileMetadata] = []

        try:
            lines: List[str] = []
            self.client.retrlines(f"LIST {path}", lines.append)

            for line in lines:
                parts = line.split(maxsplit=8)
                if len(parts) < 9:
                    continue

                perms, _, owner, group, size, month, day, time_year, name = parts
                result.append(
                    FileMetadata(
                        path=f"{path}/{name}".replace("//", "/"),
                        is_dir=perms.startswith("d"),
                        size=int(size),
                        permissions=perms,
                        owner=owner,
                        group=group,
                        modified_time=f"{month} {day} {time_year}",
                    )
                )

        except error_perm:
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
        with open(local_path, "wb") as f:
            self.client.retrbinary(f"RETR {remote_path}", f.write)

    # -------------------------------------------------
    # Lifecycle
    # -------------------------------------------------
    def close(self):
        try:
            self.client.quit()
        except Exception:
            try:
                self.client.close()
            except Exception:
                pass
