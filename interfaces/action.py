from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from interfaces.session import Session
from dto import ActionResult


class Action(ABC):
    """
    Represents a high-level operation executed on a remote Session.

    Actions:
    - do not maintain state
    - are protocol-agnostic
    - rely only on Session interface
    - return ActionResult
    """

    name: str = "generic"
    description: str = ""

    @abstractmethod
    def execute(
        self,
        session: Session,
        **kwargs
    ) -> ActionResult:
        """
        Execute the action using the given session.

        Args:
            session (Session): Active session for a protocol (SSH, FTP, etc)
            **kwargs: Action-specific parameters

        Returns:
            ActionResult: Unified execution result
        """
        pass

    def supports(self, session: Session) -> bool:
        """
        Optional hook to validate whether this Action
        can be executed on the given Session.

        Default: True (assume compatible).
        """
        return True
