"""Ізольовані дані та заборона справжніх HTTP-запитів у всіх тестах."""

import json
from copy import deepcopy
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def payload():
    path = Path(__file__).parents[1] / "data" / "nvd_sample.json"
    return deepcopy(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def cve(payload):
    return payload["vulnerabilities"][0]["cve"]


@pytest.fixture
def metric(cve):
    return cve["metrics"]["cvssMetricV31"][0]


@pytest.fixture
def expected_report():
    return {
        "cve_id": "CVE-2099-10001",
        "variant": 2,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
        "observed": "LOW",
        "decision": "review",
    }
