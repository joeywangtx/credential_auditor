from pathlib import Path

from credaudit.secrets_scan import _scan_file, scan_local_configs


def test_detects_aws_access_key(tmp_path):
    f = tmp_path / "credentials"
    f.write_text("aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n")

    findings = _scan_file(f)

    assert any("AWS Access Key" in x.title for x in findings)
    assert findings[0].severity.value == "CRITICAL"


def test_detects_password_assignment(tmp_path):
    f = tmp_path / "config.ini"
    f.write_text("db_password = SuperSecret123!\n")

    findings = _scan_file(f)

    assert any(x.category == "plaintext_secret" for x in findings)


def test_redacts_secret_value_in_output(tmp_path):
    f = tmp_path / ".env"
    f.write_text("API_KEY=abcdef1234567890abcdef1234567890\n")

    findings = _scan_file(f)

    assert findings
    assert "abcdef1234567890abcdef1234567890" not in findings[0].detail


def test_ignores_placeholder_values(tmp_path):
    f = tmp_path / ".env"
    f.write_text("password=CHANGEME\napi_key=<your-key-here>\n")

    findings = _scan_file(f)

    assert findings == []


def test_skips_binary_extensions(tmp_path):
    f = tmp_path / "image.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\napi_key=abcdef1234567890abcdef1234567890")

    findings = _scan_file(f)

    assert findings == []


def test_scan_local_configs_walks_extra_root(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text("SECRET_TOKEN=abcdef1234567890abcdef1234567890\n")

    findings = scan_local_configs(extra_roots=[project])

    assert any(f.location.endswith(".env") for f in findings)
