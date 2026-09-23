from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
from typing import Any

from .errors import InputValidationError, SnapshotValidationError
from .models import SCHEMA_VERSION, VERSION

COMPLETION_RE = re.compile(r"^Filesystem hash complete\. Hashed (?P<count>\d+) files\.\s*$")
PROMPT_RE = re.compile(r"^\s*(?P<hostname>.+?)\s+(?P<prompt>[#$])(?:\s+diagnose\s+sys\s+filesystem\s+hash)?\s*$")
HASH_RE = re.compile(r"^(?P<hash>[0-9A-Fa-f]{64})\s+(?P<path>/.*)$")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _strip_ansi(line: str) -> str:
    return ANSI_RE.sub("", line).rstrip("\r")


def parse_raw_hash_output(raw: str, hostname_override: str | None = None) -> dict[str, Any]:
    """Strictly parse completed FortiGate filesystem-hash evidence.

    Unknown lines, read errors, malformed hashes, duplicate paths, missing
    completion markers, and record-count mismatches all fail closed.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise SnapshotValidationError("Raw filesystem-hash evidence is empty.")

    files: dict[str, str] = {}
    hostname: str | None = None
    reported_files: int | None = None
    completion_seen = False

    for line_number, original_line in enumerate(raw.splitlines(), start=1):
        line = _strip_ansi(original_line).strip()
        if not line:
            continue

        prompt_match = PROMPT_RE.fullmatch(line)
        if prompt_match:
            hostname = hostname or prompt_match.group("hostname").strip()
            continue

        if line == "diagnose sys filesystem hash" or line.startswith("Hash contents:"):
            continue

        completion_match = COMPLETION_RE.fullmatch(line)
        if completion_match:
            if completion_seen:
                raise SnapshotValidationError(f"Duplicate completion marker at line {line_number}.")
            reported_files = int(completion_match.group("count"))
            completion_seen = True
            continue

        if line.startswith("Error reading simlink for file") or line.startswith("Error reading file"):
            raise SnapshotValidationError(
                f"FortiOS reported a filesystem read error at line {line_number}: {line}"
            )

        record_match = HASH_RE.fullmatch(line)
        if record_match:
            file_hash = record_match.group("hash").lower()
            path = record_match.group("path").strip()
            if " -> " in path:
                path = path.split(" -> ", 1)[0].rstrip()
            if not path.startswith("/") or "\x00" in path:
                raise SnapshotValidationError(f"Invalid filesystem path at line {line_number}.")
            if path in files:
                raise SnapshotValidationError(f"Duplicate filesystem path at line {line_number}: {path}")
            files[path] = file_hash
            continue

        raise SnapshotValidationError(
            f"Unrecognized or malformed filesystem-hash output at line {line_number}: {line}"
        )

    if not completion_seen or reported_files is None:
        raise SnapshotValidationError("Missing FortiOS filesystem-hash completion marker.")
    if reported_files != len(files):
        raise SnapshotValidationError(
            f"Filesystem-hash record-count mismatch: FortiOS reported {reported_files}, "
            f"but the parser accepted {len(files)}."
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "hostname": hostname_override or hostname or "UNKNOWN-HOSTNAME",
            "collection_status": "complete",
            "reported_files": reported_files,
            "parsed_files": len(files),
            "collected_at": _utc_now(),
            "collector_version": VERSION,
        },
        "files": files,
    }


def validate_snapshot(snapshot: Any) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise SnapshotValidationError("Snapshot JSON must be an object.")
    if "schema_version" not in snapshot:
        raise SnapshotValidationError(
            "Legacy JSON snapshot rejected: it lacks completeness metadata. "
            "Re-collect the baseline or re-parse retained raw evidence containing the FortiOS completion marker."
        )
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotValidationError(f"Unsupported snapshot schema version: {snapshot.get('schema_version')!r}.")

    metadata = snapshot.get("metadata")
    files = snapshot.get("files")
    if not isinstance(metadata, dict) or not isinstance(files, dict):
        raise SnapshotValidationError("Snapshot must contain metadata and files objects.")
    if metadata.get("collection_status") != "complete":
        raise SnapshotValidationError("Snapshot collection_status is not complete.")

    reported = metadata.get("reported_files")
    parsed = metadata.get("parsed_files")
    if not isinstance(reported, int) or not isinstance(parsed, int):
        raise SnapshotValidationError("Snapshot file-count metadata is missing or invalid.")
    if reported != parsed or parsed != len(files):
        raise SnapshotValidationError("Snapshot file-count metadata does not match the stored file records.")

    normalized_files: dict[str, str] = {}
    for path, file_hash in files.items():
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            raise SnapshotValidationError(f"Invalid stored filesystem path: {path!r}")
        if not isinstance(file_hash, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", file_hash):
            raise SnapshotValidationError(f"Invalid SHA-256 value for path: {path}")
        normalized_files[path] = file_hash.lower()

    normalized = json.loads(json.dumps(snapshot))
    normalized["files"] = normalized_files
    return normalized


def load_snapshot(source: str | dict[str, Any], hostname_override: str | None = None) -> dict[str, Any]:
    if isinstance(source, dict):
        return validate_snapshot(source)

    path = Path(source)
    if not path.is_file():
        raise InputValidationError(f"Input file does not exist: {source}")
    text = path.read_text(encoding="utf-8")
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return parse_raw_hash_output(text, hostname_override=hostname_override)
    return validate_snapshot(decoded)


def compare_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_files = validate_snapshot(old)["files"]
    new_files = validate_snapshot(new)["files"]
    added = {p: new_files[p] for p in sorted(new_files.keys() - old_files.keys())}
    removed = {p: old_files[p] for p in sorted(old_files.keys() - new_files.keys())}
    modified = {
        p: {"old": old_files[p], "new": new_files[p]}
        for p in sorted(old_files.keys() & new_files.keys())
        if old_files[p] != new_files[p]
    }
    changed = bool(added or removed or modified)
    return {
        "status": "FILESYSTEM_CHANGES_DETECTED" if changed else "NO_FILESYSTEM_CHANGES_DETECTED",
        "added": added,
        "removed": removed,
        "modified": modified,
    }
