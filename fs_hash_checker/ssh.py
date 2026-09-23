from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from typing import Any

from .errors import CollectionError, InputValidationError
from .models import (
    DEFAULT_COLLECTION_TIMEOUT,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_SSH_PORT,
    PTY_HEIGHT,
    PTY_WIDTH,
)

COMPLETION_SEARCH_RE = re.compile(
    r"(?:^|[\r\n])Filesystem hash complete\. Hashed \d+ files\.(?:[\r\n]|$)"
)
SHA256_PIN_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")


def normalize_pin(pin: str) -> str:
    value = pin.strip()
    if not SHA256_PIN_RE.fullmatch(value):
        raise InputValidationError("Host-key pin must use OpenSSH SHA256:<base64> format.")
    return value.rstrip("=")


def host_key_sha256(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def make_pinned_policy(paramiko_module: Any, expected_pin: str) -> Any:
    expected = normalize_pin(expected_pin)

    class PinnedFingerprintPolicy(paramiko_module.MissingHostKeyPolicy):
        def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
            actual = host_key_sha256(key.asbytes())
            if actual != expected:
                raise paramiko_module.SSHException(
                    f"Unknown SSH host key for {hostname}; fingerprint mismatch "
                    f"(expected {expected}, got {actual})."
                )
            # Exact pin accepted for this in-memory connection only.
            # The tool never persists an unknown host key automatically.

    return PinnedFingerprintPolicy()


def verify_connected_host_key_pin(ssh_client: Any, expected_pin: str, hostname: str) -> None:
    expected = normalize_pin(expected_pin)
    transport = ssh_client.get_transport()
    if transport is None or not transport.is_active():
        raise CollectionError(
            f"Unable to verify the SSH host-key fingerprint for {hostname}; transport is not active."
        )
    remote_key = transport.get_remote_server_key()
    actual = host_key_sha256(remote_key.asbytes())
    if actual != expected:
        raise CollectionError(
            f"SSH host-key fingerprint mismatch for {hostname}; "
            f"expected {expected}, got {actual}."
        )


def read_until_completion(channel: Any, collection_timeout: float, idle_timeout: float) -> str:
    if collection_timeout <= 0 or idle_timeout <= 0:
        raise InputValidationError("Collection and idle timeouts must be positive values.")

    output = ""
    started = time.monotonic()
    last_data = started
    while True:
        now = time.monotonic()
        if now - started > collection_timeout:
            raise CollectionError(
                f"Filesystem-hash collection exceeded {collection_timeout:g}s overall timeout.", output
            )
        if now - last_data > idle_timeout:
            raise CollectionError(
                f"Filesystem-hash collection exceeded {idle_timeout:g}s idle timeout.", output
            )

        try:
            ready = channel.recv_ready()
        except Exception as exc:
            raise CollectionError(f"Unable to query SSH channel state: {exc}", output) from exc

        if not ready:
            if getattr(channel, "closed", False):
                raise CollectionError(
                    "SSH channel closed before the completion marker was received.", output
                )
            time.sleep(0.05)
            continue

        try:
            chunk = channel.recv(65535)
        except Exception as exc:
            raise CollectionError(f"SSH receive failed before collection completed: {exc}", output) from exc
        if not chunk:
            raise CollectionError(
                "SSH channel reached EOF before the completion marker was received.", output
            )
        try:
            decoded = chunk.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CollectionError("FortiGate output was not valid UTF-8.", output) from exc

        output += decoded
        last_data = time.monotonic()
        if COMPLETION_SEARCH_RE.search(output):
            return output


def _drain_ready(channel: Any) -> None:
    while channel.recv_ready():
        chunk = channel.recv(65535)
        if not chunk:
            break
        chunk.decode("utf-8", errors="replace")


def collect_raw_hashes(
    fortigate: str,
    username: str,
    ssh_port: int = DEFAULT_SSH_PORT,
    *,
    known_hosts: str | None = None,
    host_key_sha256_pin: str | None = None,
    identity_file: str | None = None,
    password: str | None = None,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    collection_timeout: float = DEFAULT_COLLECTION_TIMEOUT,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
) -> str:
    if not fortigate or not username:
        raise InputValidationError("FortiGate address and username are required for SSH collection.")
    if not 1 <= int(ssh_port) <= 65535:
        raise InputValidationError("SSH port must be between 1 and 65535.")

    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise CollectionError("Paramiko is required for SSH collection.") from exc

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if known_hosts:
        known_hosts_path = os.path.expanduser(known_hosts)
        if not os.path.isfile(known_hosts_path):
            raise InputValidationError(f"known_hosts file does not exist: {known_hosts}")
        ssh.load_host_keys(known_hosts_path)

    if host_key_sha256_pin:
        ssh.set_missing_host_key_policy(make_pinned_policy(paramiko, host_key_sha256_pin))
    else:
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        ssh.connect(
            fortigate,
            port=int(ssh_port),
            username=username,
            password=password,
            key_filename=os.path.expanduser(identity_file) if identity_file else None,
            look_for_keys=True,
            allow_agent=True,
            timeout=connect_timeout,
            auth_timeout=connect_timeout,
            banner_timeout=connect_timeout,
        )
        if host_key_sha256_pin:
            verify_connected_host_key_pin(ssh, host_key_sha256_pin, fortigate)

        channel = ssh.invoke_shell(term="vt100", width=PTY_WIDTH, height=PTY_HEIGHT)
        _drain_ready(channel)
        channel.send("diagnose sys filesystem hash\n")
        return read_until_completion(channel, collection_timeout, idle_timeout)
    except paramiko.BadHostKeyException as exc:
        raise CollectionError(f"SSH host-key mismatch for {fortigate}; connection rejected.") from exc
    except paramiko.AuthenticationException as exc:
        raise CollectionError(f"SSH authentication failed for {fortigate}.") from exc
    except paramiko.SSHException as exc:
        raise CollectionError(f"SSH collection failed for {fortigate}: {exc}") from exc
    except OSError as exc:
        raise CollectionError(f"SSH connection to {fortigate} failed: {exc}") from exc
    finally:
        ssh.close()
