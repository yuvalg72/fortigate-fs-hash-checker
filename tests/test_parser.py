import json
from pathlib import Path

import pytest

import fs_hash_checker as fhc

H1 = "a" * 64
H2 = "b" * 64


def raw(*records, hostname="FGT-01", prompt="#", reported=None):
    if reported is None:
        reported = len(records)
    lines = [f"{hostname} {prompt} diagnose sys filesystem hash", "Hash contents: /bin"]
    lines.extend(records)
    lines.append(f"Filesystem hash complete. Hashed {reported} files.")
    return "\n".join(lines) + "\n"


def test_valid_hash_output_and_symlink():
    snapshot = fhc.parse_raw_hash_output(
        raw(f"{H1}        /bin/a", f"{H2}        /bin/link -> /bin/a")
    )
    assert snapshot["metadata"]["hostname"] == "FGT-01"
    assert snapshot["metadata"]["reported_files"] == 2
    assert snapshot["metadata"]["parsed_files"] == 2
    assert snapshot["files"]["/bin/link"] == H2


def test_dollar_prompt_supported():
    snapshot = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a", prompt="$"))
    assert snapshot["metadata"]["hostname"] == "FGT-01"


def test_hostname_override_wins():
    snapshot = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a"), hostname_override="Override")
    assert snapshot["metadata"]["hostname"] == "Override"


def test_missing_completion_is_rejected():
    evidence = f"FGT-01 # diagnose sys filesystem hash\n{H1} /bin/a\n"
    with pytest.raises(fhc.SnapshotValidationError, match="completion marker"):
        fhc.parse_raw_hash_output(evidence)


def test_reported_count_mismatch_is_rejected():
    with pytest.raises(fhc.SnapshotValidationError, match="record-count mismatch"):
        fhc.parse_raw_hash_output(raw(f"{H1} /bin/a", reported=2))


def test_invalid_hash_is_rejected():
    with pytest.raises(fhc.SnapshotValidationError, match="Unrecognized or malformed"):
        fhc.parse_raw_hash_output(raw("abc123 /bin/a"))


def test_duplicate_path_is_rejected():
    with pytest.raises(fhc.SnapshotValidationError, match="Duplicate filesystem path"):
        fhc.parse_raw_hash_output(raw(f"{H1} /bin/a", f"{H2} /bin/a"))


def test_wrapped_continuation_is_rejected():
    evidence = raw(f"{H1} /very/long/path")
    evidence = evidence.replace("/very/long/path", "/very/long\n/path")
    with pytest.raises(fhc.SnapshotValidationError, match="Unrecognized or malformed"):
        fhc.parse_raw_hash_output(evidence)


def test_read_error_is_rejected():
    evidence = raw(f"{H1} /bin/a").replace(
        f"{H1} /bin/a", "Error reading file /bin/a"
    ).replace("Hashed 1 files", "Hashed 0 files")
    with pytest.raises(fhc.SnapshotValidationError, match="read error"):
        fhc.parse_raw_hash_output(evidence)


def test_legacy_json_is_rejected(tmp_path: Path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"/bin/a": H1, "hostname": "FGT-01"}), encoding="utf-8")
    with pytest.raises(fhc.SnapshotValidationError, match="Legacy JSON snapshot rejected"):
        fhc.load_snapshot(str(path))


def test_snapshot_count_metadata_tampering_is_rejected():
    snapshot = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a"))
    snapshot["metadata"]["parsed_files"] = 2
    with pytest.raises(fhc.SnapshotValidationError, match="file-count metadata"):
        fhc.validate_snapshot(snapshot)


def test_compare_reports_added_removed_modified():
    old = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a", f"{H1} /bin/removed"))
    new = fhc.parse_raw_hash_output(raw(f"{H2} /bin/a", f"{H1} /bin/added"))
    result = fhc.compare_snapshots(old, new)
    assert result["status"] == "FILESYSTEM_CHANGES_DETECTED"
    assert "/bin/a" in result["modified"]
    assert "/bin/added" in result["added"]
    assert "/bin/removed" in result["removed"]


def test_compare_no_changes_uses_scoped_status():
    old = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a"))
    new = fhc.parse_raw_hash_output(raw(f"{H1} /bin/a"))
    result = fhc.compare_snapshots(old, new)
    assert result["status"] == "NO_FILESYSTEM_CHANGES_DETECTED"


@pytest.mark.parametrize("length", [81, 161, 241])
def test_long_paths_remain_single_records(length):
    path = "/" + ("x" * (length - 1))
    snapshot = fhc.parse_raw_hash_output(raw(f"{H1} {path}"))
    assert path in snapshot["files"]


def test_malformed_prompt_does_not_crash_hostname_extraction():
    evidence = "FGT # unexpected text\nFilesystem hash complete. Hashed 0 files.\n"
    with pytest.raises(fhc.SnapshotValidationError, match="Unrecognized or malformed"):
        fhc.parse_raw_hash_output(evidence)
