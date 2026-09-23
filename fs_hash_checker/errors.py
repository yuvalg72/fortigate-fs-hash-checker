class HashCheckerError(Exception):
    """Base class for expected operator-facing failures."""


class InputValidationError(HashCheckerError):
    pass


class CollectionError(HashCheckerError):
    def __init__(self, message: str, partial_output: str = "") -> None:
        super().__init__(message)
        self.partial_output = partial_output


class SnapshotValidationError(HashCheckerError):
    pass
