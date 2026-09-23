from __future__ import annotations

import csv
import datetime as dt
import json
import os
from pathlib import Path
import re
from typing import Any

from .errors import InputValidationError
from .models import CsvEntry, DEFAULT_SSH_PORT, Target


def sanitize_hostname(value: str | None) -> str:
    candidate = (value or "UNKNOWN-HOSTNAME").strip() or "UNKNOWN-HOSTNAME"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", candidate)[:128]


def ensure_output_dir(output_path: str | None) -> Path | None:
    if not output_path:
        return None
    output_dir = Path(output_path).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_private_text(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def save_snapshot(snapshot: dict[str, Any], output_path: str, hostname_override: str | None = None) -> Path:
    output_dir = ensure_output_dir(output_path)
    if output_dir is None:
        raise InputValidationError("Output path is required to save a snapshot.")
    hostname = sanitize_hostname(hostname_override or snapshot.get("metadata", {}).get("hostname"))
    destination = output_dir / (
        f"{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{hostname}_fortigate_fs_hashes.json"
    )
    write_private_text(destination, json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    return destination


def save_failed_collection(partial_output: str, output_path: str | None, hostname_hint: str | None) -> Path | None:
    output_dir = ensure_output_dir(output_path)
    if output_dir is None or not partial_output:
        return None
    destination = output_dir / (
        f"{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{sanitize_hostname(hostname_hint)}_collection_failed.txt"
    )
    write_private_text(destination, partial_output)
    return destination


def save_comparison(result: dict[str, Any], output_path: str | None, hostname: str) -> Path | None:
    output_dir = ensure_output_dir(output_path)
    if output_dir is None:
        return None
    destination = output_dir / (
        f"{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{sanitize_hostname(hostname)}"
        "_fortigate_fs_hash_comparison_result.json"
    )
    write_private_text(destination, json.dumps(result, indent=2, sort_keys=True) + "\n")
    return destination


def parse_ssh_port(value: str | int | None, row_number: int | None = None) -> int:
    if value is None or str(value).strip() == "":
        return DEFAULT_SSH_PORT
    try:
        port = int(str(value).strip())
    except ValueError as exc:
        where = f" in CSV row {row_number}" if row_number is not None else ""
        raise InputValidationError(f"Invalid SSH port{where}: {value!r}") from exc
    if not 1 <= port <= 65535:
        where = f" in CSV row {row_number}" if row_number is not None else ""
        raise InputValidationError(f"SSH port out of range{where}: {port}")
    return port


def read_csv_entries(csv_path: str) -> list[CsvEntry]:
    path = Path(csv_path)
    if not path.is_file():
        raise InputValidationError(f"CSV file does not exist: {csv_path}")

    entries: list[CsvEntry] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = set(reader.fieldnames or [])
        if "password" in headers:
            raise InputValidationError(
                "CSV password columns are not supported. Use SSH agent/key authentication for batch collection."
            )
        required = {"fortigate", "username", "ssh_port", "fortigate_hostname", "input_old", "input_new", "output"}
        missing = required - headers
        if missing:
            raise InputValidationError("CSV is missing required columns: " + ", ".join(sorted(missing)))

        for row_number, row in enumerate(reader, start=2):
            clean = {key: (value or "").strip() for key, value in row.items() if key is not None}
            if not any(clean.values()):
                entries.append(CsvEntry(row_number=row_number, skipped=True))
                continue
            try:
                input_new = clean.get("input_new") or None
                fortigate = clean.get("fortigate") or None
                username = clean.get("username") or None
                if input_new is None and (not fortigate or not username):
                    raise InputValidationError(
                        "fortigate and username are required when input_new is empty"
                    )
                target = Target(
                    fortigate=fortigate,
                    username=username,
                    ssh_port=parse_ssh_port(clean.get("ssh_port"), row_number),
                    fortigate_hostname=clean.get("fortigate_hostname") or None,
                    input_old=clean.get("input_old") or None,
                    input_new=input_new,
                    output=clean.get("output") or None,
                    known_hosts=clean.get("known_hosts") or None,
                    host_key_sha256=clean.get("host_key_sha256") or None,
                    identity_file=clean.get("identity_file") or None,
                )
                entries.append(CsvEntry(row_number=row_number, target=target))
            except InputValidationError as exc:
                entries.append(CsvEntry(row_number=row_number, error=str(exc)))
    return entries
