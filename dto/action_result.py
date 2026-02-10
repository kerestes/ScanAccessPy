class ActionResult:
    def __init__(
        self,
        success: bool,
        stdout: str = "",
        stderr: str = "",
        banner: str = "",
        raw: Any = None
    ):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.banner = banner
        self.raw = raw
