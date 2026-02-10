from dataclasses import dataclass
from typing import Optional

@dataclass
class FileMetadata:
    path: str
    is_dir: bool
    size: Optional[int] = None
    permissions: Optional[str] = None
    owner: Optional[str] = None
    group: Optional[str] = None
    modified_time: Optional[str] = None
