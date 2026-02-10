from enums import AccessLevel, AccessFailure

class AccessResult:
    def __init__(
        self,
        level: AccessLevel,
        failure: AccessFailure = AccessFailure.NONE,
        message: str = None
    ):
        self.level = level
        self.failure = failure
        self.message = message

    @property
    def success(self) -> bool:
        return self.level != AccessLevel.NONE

    def to_dict(self):
        return {
            "access_level": self.level.value,
            "failure": self.failure.value,
            "message": self.message,
        }
