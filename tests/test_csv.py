from pathlib import Path

import pytest

from fs_hash_checker.io import read_csv_entries
import fs_hash_checker as fhc


def test_csv_rejects_password_column(tmp_path: Path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "fortigate,username,password,ssh_port,fortigate_hostname,input_old,input_new,output\n"
        "10.0.0.1,admin,secret,22,FGT,,,out\n",
        encoding="utf-8",
    )
    with pytest.raises(fhc.InputValidationError, match="password columns"):
        read_csv_entries(str(path))


def test_csv_defaults_empty_ssh_port_to_22(tmp_path: Path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "fortigate,username,ssh_port,fortigate_hostname,input_old,input_new,output,known_hosts,host_key_sha256,identity_file\n"
        "10.0.0.1,admin,,FGT,,,,,,\n",
        encoding="utf-8",
    )
    entries = read_csv_entries(str(path))
    assert entries[0].target.ssh_port == 22
    assert entries[0].error is None


def test_file_only_csv_row_does_not_require_ssh_identity(tmp_path: Path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "fortigate,username,ssh_port,fortigate_hostname,input_old,input_new,output\n"
        ",,,FGT,old.raw,new.raw,out\n",
        encoding="utf-8",
    )
    entries = read_csv_entries(str(path))
    assert entries[0].target.fortigate is None
    assert entries[0].target.input_new == "new.raw"


def test_invalid_csv_port_isolated_to_row(tmp_path: Path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "fortigate,username,ssh_port,fortigate_hostname,input_old,input_new,output\n"
        "10.0.0.1,admin,nope,FGT,,,,\n"
        ",,,FGT2,old.raw,new.raw,out\n",
        encoding="utf-8",
    )
    entries = read_csv_entries(str(path))
    assert entries[0].row_number == 2
    assert "row 2" in entries[0].error
    assert entries[1].target.input_new == "new.raw"


def test_all_empty_csv_row_is_skipped(tmp_path: Path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "fortigate,username,ssh_port,fortigate_hostname,input_old,input_new,output\n"
        ",,,,,,\n",
        encoding="utf-8",
    )
    entries = read_csv_entries(str(path))
    assert entries[0].skipped is True
