"""Перевірка справжнього клієнта з підміною лише requests.get."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


@pytest.mark.parametrize(
    "key, expected",
    [
        (None, None),
        ("", None),
        (" \t ", None),
        ("fictional-test-key", "fictional-test-key"),
        ("  fictional-test-key \n", "fictional-test-key"),
    ],
)
def test_headers_read_environment_on_each_call(monkeypatch, key, expected):
    assert api_client.build_headers() == {"Accept": "application/json"}
    if key is not None:
        monkeypatch.setenv("NVD_API_KEY", key)
    headers = {"Accept": "application/json"}
    if expected is not None:
        headers["apiKey"] = expected
    assert api_client.build_headers() == headers
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("key", [None, "  fictional-test-key  "])
def test_fetch_uses_expected_request(monkeypatch, payload, key):
    headers = {"Accept": "application/json"}
    if key is not None:
        monkeypatch.setenv("NVD_API_KEY", key)
        headers["apiKey"] = "fictional-test-key"
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response(CVE_ID) == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE_ID},
        headers=headers,
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()
    response.json.assert_called_once_with()
    assert response.method_calls[:2] == [("raise_for_status", (), {}), ("json", (), {})]


@pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
def test_http_error(monkeypatch, status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.raise_for_status.side_effect = requests.HTTPError(response=response)
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    with pytest.raises(requests.HTTPError):
        api_client.fetch_response(CVE_ID)
    response.raise_for_status.assert_called_once_with()
    response.json.assert_not_called()
    assert fake_get.call_count == 1


@pytest.mark.parametrize("status", [201, 204, 301, 302, 304, 307, 308])
def test_unexpected_status_and_redirects(monkeypatch, status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    with pytest.raises(requests.HTTPError) as error:
        api_client.fetch_response(CVE_ID)
    assert error.value.response.status_code == status
    assert fake_get.call_args.kwargs["allow_redirects"] is False
    assert fake_get.call_count == 1
    response.raise_for_status.assert_called_once_with()
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "error_type",
    [
        requests.ConnectionError,
        requests.Timeout,
        requests.ConnectTimeout,
        requests.ReadTimeout,
    ],
)
def test_connection_and_timeout_not_retried(monkeypatch, error_type):
    fake_get = Mock(side_effect=error_type("Тестова помилка"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    with pytest.raises(error_type):
        api_client.fetch_response(CVE_ID)
    fake_get.assert_called_once()


def test_invalid_json(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE_ID)
    response.raise_for_status.assert_called_once_with()


def test_network_guard_is_active():
    assert not hasattr(requests.sessions.Session, "request")
    with pytest.raises(AttributeError):
        requests.get("https://example.invalid")
