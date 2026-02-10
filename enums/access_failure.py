from enum import Enum

class AccessFailure(Enum):
    NONE = "NONE"                 # sucesso
    AUTH_FAILED = "AUTH_FAILED"
    TIMEOUT = "TIMEOUT"
    PORT_CLOSED = "PORT_CLOSED"
    HOST_UNREACHABLE = "HOST_UNREACHABLE"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    TLS_ERROR = "TLS_ERROR"
    UNKNOWN = "UNKNOWN"
