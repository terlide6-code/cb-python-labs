"""Інтеграційні перевірки CLI, локального файла й безпечних помилок."""

import importlib
import json
import runpy
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import analysis, api_client, main

CVE_ID = "CVE-2099-10001"


def _write_payload(tmp_path, payload):
    path = tmp_path / "response.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _assert_failure(capsys, text):
    captured = capsys.readouterr()
    assert captured.out == ""
    assert text in captured.err
    assert "Traceback" not in captured.err
    assert "fictional-sensitive-value" not in captured.err


def test_local_mode_exact_json_and_no_network(
    tmp_path, payload, expected_report, monkeypatch, capsys
):
    path = _write_payload(tmp_path, payload)
    fake_get = Mock(side_effect=AssertionError("Локальний режим не потребує HTTP."))
    fake_fetch = Mock(
        side_effect=AssertionError("Локальний режим не потребує клієнта.")
    )
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected_report
    assert captured.err == ""
    fake_get.assert_not_called()
    fake_fetch.assert_not_called()


def test_unicode_stdout(tmp_path, payload, cve, capsys):
    cve["descriptions"][0]["value"] = "Навчальний англомовний запис із Unicode"
    path = _write_payload(tmp_path, payload)
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    captured = capsys.readouterr()
    assert "Навчальний" in captured.out
    assert "\\u" not in captured.out
    assert captured.err == ""


def test_network_mode_integrates_real_client(
    monkeypatch, payload, expected_report, capsys
):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert main.main(["--cve", CVE_ID]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected_report
    assert captured.err == ""
    fake_get.assert_called_once()


def test_load_response(tmp_path, payload):
    path = _write_payload(tmp_path, payload)
    assert main.load_response(path) == payload
    assert main.load_response(str(path)) == payload


@pytest.mark.parametrize(
    "mode",
    [
        "invalid_json",
        "missing_file",
        "directory",
        "invalid_utf8",
        "wrong_structure",
        "wrong_cve",
        "invalid_field",
    ],
)
def test_local_failures(tmp_path, payload, cve, metric, capsys, mode):
    path = tmp_path / "response.json"
    if mode == "invalid_json":
        path.write_text('{"fictional-sensitive-value":', encoding="utf-8")
    elif mode == "directory":
        path.mkdir()
    elif mode == "invalid_utf8":
        path.write_bytes(b"\xff")
    elif mode == "wrong_structure":
        path = _write_payload(tmp_path, [])
    elif mode == "wrong_cve":
        cve["id"] = "CVE-2021-44228"
        path = _write_payload(tmp_path, payload)
    elif mode == "invalid_field":
        metric["cvssData"]["attackComplexity"] = None
        path = _write_payload(tmp_path, payload)
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 1
    _assert_failure(capsys, "Помилка:")


def test_unreadable_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        main,
        "load_response",
        Mock(side_effect=PermissionError("fictional-sensitive-value")),
    )
    assert main.main(["--cve", CVE_ID, "--input", str(tmp_path / "private.json")]) == 1
    _assert_failure(capsys, "прочитати")


@pytest.mark.parametrize(
    "cve_id",
    [
        "cve-2021-44228",
        "CVE-21-44228",
        "CVE-2021-123",
        "CVE-2021-44228x",
        "xCVE-2021-44228",
        "CVE-２０２１-44228",
        "CVE-2021-44228\n",
        " CVE-2021-44228",
        "",
    ],
)
def test_invalid_cve_arguments(cve_id, capsys):
    with pytest.raises(SystemExit) as error:
        main.main(["--cve", cve_id])
    assert error.value.code == 2
    _assert_failure(capsys, "Помилка аргументів")


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--input", "sample.json"],
        ["--cve"],
        ["--cve", CVE_ID, "--variant", "2"],
        ["--cv", CVE_ID],
        ["--cve", CVE_ID, "--input"],
    ],
)
def test_argument_errors(argv, capsys):
    with pytest.raises(SystemExit) as error:
        main.main(argv)
    assert error.value.code == 2
    _assert_failure(capsys, "Помилка аргументів")


@pytest.mark.parametrize("cve_id", ["CVE-0000-0000", "CVE-2099-123456789"])
def test_format_does_not_restrict_year_or_sequence(cve_id, monkeypatch, capsys):
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(return_value={"vulnerabilities": []})
    )
    assert main.main(["--cve", cve_id]) == 0
    assert json.loads(capsys.readouterr().out)["cve_id"] == cve_id


@pytest.mark.parametrize("variant", [True, False, 0, 16, -1, "2", 2.0, None])
def test_invalid_variant_before_io(variant, monkeypatch, capsys):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    fake_fetch = Mock(side_effect=AssertionError("Варіант слід перевірити до запиту."))
    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE_ID]) == 2
    _assert_failure(capsys, "номер варіанта")
    fake_fetch.assert_not_called()


@pytest.mark.parametrize(
    "mode, decision",
    [
        ("not_found", "not_found"),
        ("rejected", "rejected"),
        ("missing_status", "insufficient_data"),
        ("missing_cvss", "insufficient_data"),
        ("missing_field", "insufficient_data"),
        ("high", "other"),
    ],
)
def test_success_exit_codes_for_all_states(
    tmp_path, payload, cve, metric, capsys, mode, decision
):
    if mode == "not_found":
        payload["vulnerabilities"] = []
    elif mode == "rejected":
        cve["vulnStatus"] = "Rejected"
    elif mode == "missing_status":
        del cve["vulnStatus"]
    elif mode == "missing_cvss":
        del cve["metrics"]
    elif mode == "missing_field":
        del metric["cvssData"]["attackComplexity"]
    else:
        metric["cvssData"]["attackComplexity"] = "HIGH"
    path = _write_payload(tmp_path, payload)
    assert main.main(["--cve", CVE_ID, "--input", str(path)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["decision"] == decision
    assert captured.err == ""


@pytest.mark.parametrize(
    "error_type, message",
    [
        (requests.ConnectionError, "з'єднання"),
        (requests.Timeout, "час очікування"),
        (requests.ConnectTimeout, "час очікування"),
        (requests.ReadTimeout, "час очікування"),
        (requests.RequestException, "отримати"),
    ],
)
def test_network_errors_are_sanitized(monkeypatch, capsys, error_type, message):
    monkeypatch.setenv("NVD_API_KEY", "fictional-sensitive-value")
    fake_get = Mock(side_effect=error_type("fictional-sensitive-value"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert main.main(["--cve", CVE_ID]) == 1
    _assert_failure(capsys, message)


@pytest.mark.parametrize("status", [404, 429, 500, 302, 204])
def test_http_errors_never_mean_not_found(monkeypatch, capsys, status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.text = "fictional-sensitive-value"
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            "fictional-sensitive-value", response=response
        )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    assert main.main(["--cve", CVE_ID]) == 1
    _assert_failure(capsys, str(status))
    response.json.assert_not_called()


def test_http_error_without_response(monkeypatch, capsys):
    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(side_effect=requests.HTTPError("fictional-sensitive-value")),
    )
    assert main.main(["--cve", CVE_ID]) == 1
    _assert_failure(capsys, "HTTP-статус")


def test_network_invalid_json(monkeypatch, capsys):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "fictional-sensitive-value", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    assert main.main(["--cve", CVE_ID]) == 1
    _assert_failure(capsys, "NVD повернув некоректний JSON")


def test_help_is_ukrainian(capsys):
    with pytest.raises(SystemExit) as error:
        main.main(["--help"])
    assert error.value.code == 0
    captured = capsys.readouterr()
    assert "Використання:" in captured.out
    assert "Параметри" in captured.out
    assert captured.err == ""


def test_module_entrypoint(tmp_path, payload, monkeypatch, capsys):
    path = _write_payload(tmp_path, payload)
    monkeypatch.setattr(
        sys, "argv", ["labs.lab04.main", "--cve", CVE_ID, "--input", str(path)]
    )
    # runpy виконує окремий простір імен, зберігаючи мережеву заборону фікстури.
    monkeypatch.delitem(sys.modules, "labs.lab04.main")
    with pytest.raises(SystemExit) as error:
        runpy.run_module("labs.lab04.main", run_name="__main__")
    assert error.value.code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["decision"] == "review"
    assert captured.err == ""


def test_imports_have_no_io(monkeypatch, capsys):
    forbidden = Mock(side_effect=AssertionError("Імпорт не повинен виконувати I/O."))
    with monkeypatch.context() as context:
        context.setattr(api_client.requests, "get", forbidden)
        context.setattr(api_client.os, "getenv", forbidden)
        context.setattr(Path, "open", forbidden)
        for module in (analysis, api_client, main):
            importlib.reload(module)
    forbidden.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
