from abc import ABC, abstractmethod
from dto import OSInfo, AccessResult
from enums import AccessLevel, AccessFailure

class ConnectionTest(ABC):
    name = "BASE"

    def __init__(self, host, user=None, password=None, timeout=5):
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout
        self.session = None

    def run(self, port):
        """
        Orquestra:
        - tentativa de conexão
        - detecção de SO
        - coleta de dados
        """
        result = self.connect(port)

        if not result.success:
            return {
                "protocol": self.name,
                "port": port,
                "access": result,
                "os": None
            }

        os_info = self.detect_os(port)

        return {
            "protocol": self.name,
            "port": port,
            "access": result,
            "os": os_info
        }

    @abstractmethod
    def connect(self, port) -> AccessResult:
        """
        Must:
        - establish connection
        - authenticate if applicable
        - return AccessResult
        """
        pass

    @abstractmethod
    def detect_os(self, port) -> OSInfo:
        """
        Best-effort OS detection
        """
        pass

    @abstractmethod
    def close(self):
        """
        Gracefully close the active session
        """
        pass
