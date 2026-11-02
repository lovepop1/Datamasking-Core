"""Tests for MaskingEngine APIs and the ``datamasking`` CLI."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from datamasking import FormatParseError, MaskingEngine
from datamasking.cli.main import main as cli_main


def test_engine_max_input_bytes_and_env_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAMASKING_SALT", "env-secret-salt-value")
    eng_a = MaskingEngine({"rules": [{"selector": "$.id", "technique": "pseudonymize"}]})
    eng_b = MaskingEngine(
        {"rules": [{"selector": "$.id", "technique": "pseudonymize"}]}, salt="env-secret-salt-value"
    )
    assert eng_a.mask_data({"id": "42"}) == eng_b.mask_data({"id": "42"})

    with pytest.raises(FormatParseError, match="exceeds max_input_bytes"):
        eng_a.mask(b'{"id": "1234567890"}', max_input_bytes=5)


def test_cli_validate_techniques_formats_and_schema(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'version: "1.0"\nformat: "json"\nrules:\n  - selector: "$.ssn"\n    technique: "redact"\n',
        encoding="utf-8",
    )

    assert cli_main(["validate", "-p", str(policy_path)]) == 0
    assert "is valid" in capsys.readouterr().out

    assert cli_main(["techniques"]) == 0
    assert "pseudonymize" in capsys.readouterr().out

    assert cli_main(["techniques", "--json"]) == 0
    tech_schemas = json.loads(capsys.readouterr().out)
    assert "redact" in tech_schemas and "pseudonymize" in tech_schemas

    assert cli_main(["formats"]) == 0
    fmt_out = capsys.readouterr().out
    assert "json" in fmt_out and "zipcode" in fmt_out

    schema_file = tmp_path / "out" / "policy.schema.json"
    assert cli_main(["schema", "-o", str(schema_file)]) == 0
    assert schema_file.is_file()
    parsed_schema = json.loads(schema_file.read_text(encoding="utf-8"))
    assert parsed_schema["title"] == "DataMasking Policy Specification"


def test_cli_mask_file_dry_run_report_stdin_and_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        'version: "1.0"\nrules:\n  - selector: "$.ssn"\n    technique: "redact"\n',
        encoding="utf-8",
    )
    input_path = tmp_path / "input.json"
    input_path.write_text('{"ssn": "123-45-6789", "keep": "ok"}', encoding="utf-8")
    output_path = tmp_path / "masked.json"
    report_path = tmp_path / "report.json"

    # 1. File-to-file mask with JSON report
    code = cli_main(
        [
            "mask",
            "-i",
            str(input_path),
            "-p",
            str(policy_path),
            "-o",
            str(output_path),
            "--report",
            str(report_path),
        ]
    )
    assert code == 0
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "ssn": "[REDACTED]",
        "keep": "ok",
    }
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["unmatched_paths"] == ["$.keep"]

    # 2. Stdin ('-') with --dry-run to stdout
    fake_stdin = type("FakeStdin", (), {"buffer": io.BytesIO(b'{"ssn": "999", "keep": 1}')})()
    stdout_buf = io.BytesIO()
    fake_stdout = type("FakeStdout", (), {"buffer": stdout_buf})()
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    code_dry = cli_main(["mask", "-i", "-", "-f", "json", "-p", str(policy_path), "--dry-run"])
    assert code_dry == 0
    dry_data = json.loads(stdout_buf.getvalue().decode("utf-8"))
    assert dry_data["ssn"].startswith("[WOULD APPLY: redact")
    assert dry_data["keep"] == 1

    # 3. Missing input file returns exit code 1
    assert cli_main(["mask", "-i", str(tmp_path / "missing.json"), "-p", str(policy_path)]) == 1

    # 4. Invalid policy returns exit code 1
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("rules:\n  - selector: $.a\n    technique: nope\n", encoding="utf-8")
    assert cli_main(["validate", "-p", str(bad_policy)]) == 1
