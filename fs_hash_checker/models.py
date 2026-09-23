from dataclasses import dataclass

SCHEMA_VERSION = 2
VERSION = "0.2.0-dev"
STATUS = "Pre-production hardening"

DEFAULT_SSH_PORT = 22
DEFAULT_CONNECT_TIMEOUT = 30.0
DEFAULT_COLLECTION_TIMEOUT = 300.0
DEFAULT_IDLE_TIMEOUT = 30.0
PTY_WIDTH = 32767
PTY_HEIGHT = 1000

EXIT_OK = 0
EXIT_CHANGED = 1
EXIT_USAGE = 2
EXIT_COLLECTION_FAILED = 3
EXIT_VALIDATION_FAILED = 4
EXIT_INTERNAL_ERROR = 10


@dataclass(frozen=True)
class Target:
    fortigate: str | None = None
    username: str | None = None
    ssh_port: int = DEFAULT_SSH_PORT
    fortigate_hostname: str | None = None
    input_old: str | None = None
    input_new: str | None = None
    output: str | None = None
    known_hosts: str | None = None
    host_key_sha256: str | None = None
    identity_file: str | None = None
    prompt_password: bool = False
    collection_timeout: float = DEFAULT_COLLECTION_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT


@dataclass(frozen=True)
class CsvEntry:
    row_number: int
    target: Target | None = None
    error: str | None = None
    skipped: bool = False
