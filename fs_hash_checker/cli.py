from __future__ import annotations

import argparse
import getpass
from typing import Iterable
import sys

from .errors import CollectionError, InputValidationError, SnapshotValidationError
from .io import parse_ssh_port, read_csv_entries, save_comparison, save_failed_collection, save_snapshot
from .models import (
    DEFAULT_COLLECTION_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_SSH_PORT,
    EXIT_CHANGED,
    EXIT_COLLECTION_FAILED,
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VALIDATION_FAILED,
    Target,
)
from .parser import compare_snapshots, load_snapshot, parse_raw_hash_output
from .ssh import collect_raw_hashes


def _obtain_new_snapshot(target: Target, password: str | None = None):
    if target.input_new:
        return load_snapshot(target.input_new, hostname_override=target.fortigate_hostname), False
    raw = collect_raw_hashes(
        target.fortigate or "",
        target.username or "",
        target.ssh_port,
        known_hosts=target.known_hosts,
        host_key_sha256_pin=target.host_key_sha256,
        identity_file=target.identity_file,
        password=password,
        collection_timeout=target.collection_timeout,
        idle_timeout=target.idle_timeout,
    )
    return parse_raw_hash_output(raw, hostname_override=target.fortigate_hostname), True


def _print_comparison(result) -> None:
    for path, hashes in result["modified"].items():
        print(f"MODIFIED: {path} - NEW HASH: {hashes['new']} - OLD HASH: {hashes['old']}")
    for path, file_hash in result["added"].items():
        print(f"ADDED: {path} - HASH: {file_hash}")
    for path, file_hash in result["removed"].items():
        print(f"REMOVED: {path} - HASH: {file_hash}")
    if result["status"] == "NO_FILESYSTEM_CHANGES_DETECTED":
        print(
            "NO FILESYSTEM CHANGES DETECTED. Collection completion, parser, and record-count "
            "validation passed. Baseline provenance and FortiOS build compatibility are not yet "
            "implemented in this hardening stage."
        )


def process_target(target: Target, *, password: str | None = None) -> int:
    try:
        new_snapshot, collected = _obtain_new_snapshot(target, password=password)
    except CollectionError as exc:
        failed_path = save_failed_collection(
            exc.partial_output, target.output, target.fortigate_hostname or target.fortigate
        )
        suffix = f" Partial evidence saved to {failed_path}." if failed_path else ""
        print(f"COLLECTION_FAILED: {exc}.{suffix}", file=sys.stderr)
        return EXIT_COLLECTION_FAILED
    except (SnapshotValidationError, InputValidationError) as exc:
        print(f"VALIDATION_FAILED: {exc}", file=sys.stderr)
        return EXIT_VALIDATION_FAILED

    if collected and target.output:
        saved = save_snapshot(new_snapshot, target.output, target.fortigate_hostname)
        print(f"Validated snapshot saved to {saved}")

    if not target.input_old:
        print(
            "Snapshot collection/parsing completed with completion and record-count validation. "
            "No baseline comparison was requested."
        )
        return EXIT_OK

    try:
        old_snapshot = load_snapshot(target.input_old)
        result = compare_snapshots(old_snapshot, new_snapshot)
    except (SnapshotValidationError, InputValidationError) as exc:
        print(f"VALIDATION_FAILED: {exc}", file=sys.stderr)
        return EXIT_VALIDATION_FAILED

    hostname = (
        target.fortigate_hostname
        or new_snapshot.get("metadata", {}).get("hostname")
        or old_snapshot.get("metadata", {}).get("hostname")
        or "UNKNOWN-HOSTNAME"
    )
    print(f"Processing FortiGate {hostname} hashes...")
    _print_comparison(result)
    saved_result = save_comparison(result, target.output, hostname)
    if saved_result:
        print(f"Comparison result saved to {saved_result}")
    return EXIT_CHANGED if result["status"] == "FILESYSTEM_CHANGES_DETECTED" else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed FortiGate filesystem hash collector and comparator."
    )
    parser.add_argument("-f", "--fortigate", help="Destination FortiGate FQDN or IP address.")
    parser.add_argument("-u", "--username", help="SSH username.")
    parser.add_argument("-s", "--ssh-port", type=int, default=DEFAULT_SSH_PORT)
    parser.add_argument("-fh", "--fortigate-hostname", help="Hostname override for evidence/output names.")
    parser.add_argument("-io", "--input-old", help="Old raw or schema-v2 JSON snapshot.")
    parser.add_argument("-in", "--input-new", help="New raw or schema-v2 JSON snapshot; omit to collect over SSH.")
    parser.add_argument("-c", "--csv", help="CSV batch input. Password columns are forbidden.")
    parser.add_argument("-o", "--output", help="Output directory for snapshots/results/evidence.")
    parser.add_argument("--known-hosts", help="Additional OpenSSH known_hosts file.")
    parser.add_argument("--host-key-sha256", help="SHA256 fingerprint pin for an otherwise unknown SSH host key.")
    parser.add_argument("--identity-file", help="SSH private-key file; agent/key discovery remains enabled.")
    parser.add_argument(
        "--prompt-password",
        action="store_true",
        help="Prompt securely for an SSH password instead of placing it in argv or CSV.",
    )
    parser.add_argument("--collection-timeout", type=float, default=DEFAULT_COLLECTION_TIMEOUT)
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    return parser


def _target_from_args(args: argparse.Namespace) -> Target:
    return Target(
        fortigate=args.fortigate,
        username=args.username,
        ssh_port=parse_ssh_port(args.ssh_port),
        fortigate_hostname=args.fortigate_hostname,
        input_old=args.input_old,
        input_new=args.input_new,
        output=args.output,
        known_hosts=args.known_hosts,
        host_key_sha256=args.host_key_sha256,
        identity_file=args.identity_file,
        prompt_password=args.prompt_password,
        collection_timeout=args.collection_timeout,
        idle_timeout=args.idle_timeout,
    )


def _non_csv_args_present(args: argparse.Namespace) -> bool:
    return any(
        [
            args.fortigate,
            args.username,
            args.fortigate_hostname,
            args.input_old,
            args.input_new,
            args.output,
            args.known_hosts,
            args.host_key_sha256,
            args.identity_file,
            args.prompt_password,
            args.ssh_port != DEFAULT_SSH_PORT,
            args.collection_timeout != DEFAULT_COLLECTION_TIMEOUT,
            args.idle_timeout != DEFAULT_IDLE_TIMEOUT,
        ]
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.csv:
            if _non_csv_args_present(args):
                parser.error("When --csv is used, target-specific command-line options must not be supplied.")
            entries = read_csv_entries(args.csv)
            if not entries:
                raise InputValidationError("CSV contains no target rows.")

            statuses: list[int] = []
            skipped = 0
            for index, entry in enumerate(entries, start=1):
                print(f"--- CSV entry {index}/{len(entries)} (row {entry.row_number}) ---")
                if entry.skipped:
                    skipped += 1
                    print(f"CSV row {entry.row_number} skipped: row is empty.")
                    continue
                if entry.error:
                    print(f"CSV row {entry.row_number} VALIDATION_FAILED: {entry.error}", file=sys.stderr)
                    statuses.append(EXIT_VALIDATION_FAILED)
                    continue
                statuses.append(process_target(entry.target))

            succeeded = sum(code in (EXIT_OK, EXIT_CHANGED) for code in statuses)
            failed = len(statuses) - succeeded
            changed = sum(code == EXIT_CHANGED for code in statuses)
            print(
                f"Batch summary: succeeded={succeeded}, changed={changed}, "
                f"failed={failed}, skipped={skipped}"
            )
            if failed:
                return EXIT_COLLECTION_FAILED if EXIT_COLLECTION_FAILED in statuses else EXIT_VALIDATION_FAILED
            return EXIT_CHANGED if changed else EXIT_OK

        target = _target_from_args(args)
        if not target.input_new and (not target.fortigate or not target.username):
            raise InputValidationError(
                "Provide --input-new, or provide --fortigate and --username for SSH collection."
            )
        password = getpass.getpass("SSH password: ") if target.prompt_password else None
        return process_target(target, password=password)
    except InputValidationError as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("INTERRUPTED", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"INTERNAL_ERROR: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
