"""Чисті функції перевірки NVD і формування навчального звіту."""

import math
from copy import deepcopy

# Таблиця методички зберігає контракт для всіх допустимих номерів варіанта.
RULES = (
    (7.0, "attackVector", "NETWORK"),
    (8.0, "attackComplexity", "LOW"),
    (7.0, "privilegesRequired", "NONE"),
    (8.0, "userInteraction", "NONE"),
    (7.0, "confidentialityImpact", "HIGH"),
    (7.0, "integrityImpact", "HIGH"),
    (7.0, "availabilityImpact", "HIGH"),
    (9.0, "scope", "CHANGED"),
    (5.0, "attackVector", "LOCAL"),
    (6.0, "privilegesRequired", "LOW"),
    (6.0, "userInteraction", "REQUIRED"),
    (6.0, "confidentialityImpact", "LOW"),
    (6.0, "integrityImpact", "LOW"),
    (6.0, "availabilityImpact", "LOW"),
    (8.0, "attackComplexity", "HIGH"),
)
ALLOWED_VALUES = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": ("NONE", "LOW", "HIGH"),
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": ("NONE", "LOW", "HIGH"),
    "integrityImpact": ("NONE", "LOW", "HIGH"),
    "availabilityImpact": ("NONE", "LOW", "HIGH"),
}


class DataValidationError(ValueError):
    """Порушення контракту зовнішніх даних; підклас ValueError."""


def validate_variant(variant: int) -> None:
    """Перевірити цілий номер 1–15, відхиляючи також bool."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not 1 <= variant <= 15
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")


def _optional_string(mapping: dict, field: str) -> str | None:
    """Відрізнити відсутній рядок від некоректного наявного значення."""
    if field not in mapping:
        return None
    value = mapping[field]
    if not isinstance(value, str) or not value.strip():
        raise DataValidationError(f"Поле {field} має бути непорожнім рядком.")
    return value


def _description(cve: dict) -> str | None:
    """Перевірити всі описи й обрати перший непорожній англійський."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise DataValidationError("Поле descriptions має бути списком.")
    result = None
    for entry in descriptions:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("lang"), str)
            or not isinstance(entry.get("value"), str)
        ):
            raise DataValidationError("Опис має містити рядкові lang і value.")
        if result is None and entry["lang"] == "en" and entry["value"].strip():
            result = entry["value"]
    return result


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Перевірити відповідь і повернути незалежний внутрішній словник.

    None означає порожній пошук. Словник має description, vuln_status,
    cvss_version, score, score_source, vector та cvss_data. Останнє поле —
    глибока копія cvssData однієї вибраної оцінки або None. Загальні поля
    оцінки перевіряються тут; поле правила перевіряє лише build_report.
    Для відсутнього статусу та Rejected оцінки не читаються взагалі.
    """
    if not isinstance(payload, dict):
        raise DataValidationError("Відповідь має бути словником.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
        raise DataValidationError(
            "Поле vulnerabilities має містити нуль або один запис."
        )
    if not vulnerabilities:
        return None
    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise DataValidationError("Запис має містити словник cve.")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise DataValidationError(
            "Ідентифікатор у відповіді не відповідає запитаному CVE."
        )

    status = _optional_string(cve, "vulnStatus")
    record = {
        "description": _description(cve),
        "vuln_status": status,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }
    if status is None or status == "Rejected" or "metrics" not in cve:
        return record
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise DataValidationError("Поле metrics має бути словником.")
    if "cvssMetricV31" not in metrics:
        return record
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
        raise DataValidationError("Поле cvssMetricV31 має бути списком словників.")
    if not entries:
        return record
    selected = next((e for e in entries if e.get("type") == "Primary"), entries[0])
    data = selected.get("cvssData")
    if not isinstance(data, dict):
        raise DataValidationError("Вибрана оцінка має містити словник cvssData.")
    score = data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= score <= 10
        or not math.isfinite(score)
    ):
        raise DataValidationError(
            "Поле baseScore має бути скінченним числом від 0 до 10."
        )
    version = _optional_string(data, "version")
    if version is not None and version != "3.1":
        raise DataValidationError("Дозволена лише версія CVSS 3.1.")
    record.update(
        cvss_version=version,
        score=score,
        score_source=_optional_string(selected, "source"),
        vector=_optional_string(data, "vectorString"),
        cvss_data=deepcopy(data),
    )
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Побудувати звіт із внутрішнього запису, перевіривши поле варіанта."""
    validate_variant(variant)
    threshold, field, expected = RULES[variant - 1]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    report.update(description=record["description"], vuln_status=record["vuln_status"])
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    if record["vuln_status"] is None:
        return report
    for key in ("cvss_version", "score", "score_source", "vector"):
        report[key] = record[key]
    data = record["cvss_data"]
    if data is None or field not in data:
        return report
    observed = data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise DataValidationError(f"Поле {field} має недопустиме значення.")
    report["observed"] = observed
    report["decision"] = (
        "review" if record["score"] >= threshold and observed == expected else "other"
    )
    return report
