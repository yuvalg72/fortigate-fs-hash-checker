from pathlib import Path

import pytest

from fs_hash_checker.cli import build_parser, main
from fs_hash_checker.models import EXIT_VALIDATION_FAILED

H = "a" * 64


def raw(hostname="FGT"):
    return (
        f"{hostname} # diagnose sys filesystem hash\n"
        "Hash contents: /bin\n"
        f"{H} /bin/a\n"
        "Filesystem hash complete. Hashed 1 files.\n"
    )


def test_password_argument_does_not_exist():
    parser = build_parser()
    assert "--password" not in parser.format_help()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--password", "secret"])
    assert exc.value.code == 2


def test_mixed_csv_batch_isolates_invalid_row_and_reports_summary(tmp_path: Path, capsys):
    old = tmp_path / "old.raw"
    new = tmp_path / "new.raw"
    old.write_text(raw(), encoding="utf-8")
    new.write_text(raw(), encoding="utf-8")
    csv_path = tmp_path / "targets.csv"
    csv_path.write_text(
        "fortigate,username,ssh_port,fortigate_hostname,input_old,input_new,output\n"
        "192.0.2.1,admin,invalid,FGT,,,,\n"
        f",,,FGT,{old},{new},\n",
        encoding="utf-8",
    )

    code = main(["--csv", str(csv_path)])
    captured = capsys.readouterr()
    assert code == EXIT_VALIDATION_FAILED
    assert "CSV row 2 VALIDATION_FAILED" in captured.err
    assert "succeeded=1" in captured.out
    assert "failed=1" in captured.out
    assert "skipped=0" in captured.out
