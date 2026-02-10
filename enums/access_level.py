from enum import Enum

class AccessLevel(Enum):
    NONE = "NO_ACCESS"
    AUTHENTICATED = "AUTHENTICATED"
    USER = "USER"
    ADMIN = "ADMIN"