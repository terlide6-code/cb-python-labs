"""Один запит до NVD CVE API 2.0 без повторів і перенаправлень."""

import os

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_headers() -> dict[str, str]:
    """Сформувати заголовки, читаючи необов'язковий ключ під час виклику."""
    headers = {"Accept": "application/json"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def fetch_response(cve_id: str) -> object:
    """Отримати JSON; винятки Requests обробляє командний інтерфейс."""
    response = requests.get(
        API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.HTTPError("Неочікуваний HTTP-статус.", response=response)
    return response.json()
