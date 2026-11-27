"""Перевірка структури, вибору CVSS, станів та межі правила."""

from copy import deepcopy

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"


def test_complete_report_and_purity(payload, expected_report):
    original = deepcopy(payload)
    record = extract_record(payload, CVE_ID)
    original_record = deepcopy(record)
    assert build_report(record, CVE_ID, 2) == expected_report
    assert record == original_record
    assert payload == original
    record["cvss_data"]["attackComplexity"] = "HIGH"
    assert payload == original


@pytest.mark.parametrize(
    "score, observed, decision",
    [
        (7.9, "LOW", "other"),
        (8.0, "LOW", "review"),
        (8.1, "LOW", "review"),
        (9.8, "LOW", "review"),
        (9.8, "HIGH", "other"),
        (8.0, "HIGH", "other"),
        (0, "LOW", "other"),
        (10, "LOW", "review"),
    ],
)
def test_variant_two_boundary(payload, metric, score, observed, decision):
    metric["cvssData"].update(baseScore=score, attackComplexity=observed)
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["score"] == score
    assert report["observed"] == observed
    assert report["decision"] == decision


def test_missing_variant_field(payload, metric):
    del metric["cvssData"]["attackComplexity"]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None
    assert report["score"] == 9.8


@pytest.mark.parametrize("value", [None, "INVALID", 123, True, "low", "", [], {}])
def test_variant_field_validated_only_in_report(payload, metric, value):
    metric["cvssData"]["attackComplexity"] = value
    record = extract_record(payload, CVE_ID)
    with pytest.raises(ValueError):
        build_report(record, CVE_ID, 2)


def test_not_found(expected_report):
    expected_report.update(
        description=None,
        vuln_status=None,
        cvss_version=None,
        score=None,
        score_source=None,
        vector=None,
        observed=None,
        decision="not_found",
    )
    record = extract_record({"vulnerabilities": []}, CVE_ID)
    assert record is None
    assert build_report(record, CVE_ID, 2) == expected_report


@pytest.mark.parametrize(
    "status, decision", [(None, "insufficient_data"), ("Rejected", "rejected")]
)
@pytest.mark.parametrize("metrics", [None, [], {"cvssMetricV31": [None]}])
def test_status_priority_skips_malformed_metrics(
    payload, cve, expected_report, status, decision, metrics
):
    if status is None:
        del cve["vulnStatus"]
    else:
        cve["vulnStatus"] = status
    cve["metrics"] = metrics
    expected_report.update(
        vuln_status=status,
        cvss_version=None,
        score=None,
        score_source=None,
        vector=None,
        observed=None,
        decision=decision,
    )
    assert build_report(extract_record(payload, CVE_ID), CVE_ID, 2) == expected_report


@pytest.mark.parametrize("value", [None, "", "  ", 2, False, [], {}])
def test_invalid_status(payload, cve, value):
    cve["vulnStatus"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "bad_payload",
    [
        None,
        [],
        "text",
        1,
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": ""},
        {"vulnerabilities": [{}, {}]},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [[]]},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": None}]},
        {"vulnerabilities": [{"cve": []}]},
        {"vulnerabilities": [{"cve": {}}]},
    ],
)
def test_invalid_payload(bad_payload):
    with pytest.raises(ValueError):
        extract_record(bad_payload, CVE_ID)


@pytest.mark.parametrize("value", [None, 1, "CVE-2021-44228", "cve-2099-10001"])
def test_wrong_id(payload, cve, value):
    cve["id"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "mode", ["missing_metrics", "missing_v31", "empty_v31", "other_versions"]
)
def test_missing_cvss(payload, cve, mode):
    if mode == "missing_metrics":
        del cve["metrics"]
    elif mode == "missing_v31":
        cve["metrics"] = {}
    elif mode == "empty_v31":
        cve["metrics"] = {"cvssMetricV31": []}
    else:
        cve["metrics"] = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 10}}],
            "cvssMetricV40": [{"cvssData": {"baseScore": 10}}],
        }
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["cvss_version"] is None
    assert report["observed"] is None


@pytest.mark.parametrize("value", [None, [], "", 0, False])
def test_invalid_metrics(payload, cve, value):
    cve["metrics"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("value", [None, {}, "", 0, [None], [[]], [1], [{}, None]])
def test_invalid_v31_list(payload, cve, value):
    cve["metrics"]["cvssMetricV31"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("value", [None, [], "", 0, False])
def test_invalid_cvss_data(payload, metric, value):
    metric["cvssData"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("field", ["cvssData", "baseScore"])
def test_missing_required_score_fields(payload, metric, field):
    if field == "cvssData":
        del metric[field]
    else:
        del metric["cvssData"][field]
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        "9.8",
        -1,
        11,
        None,
        [],
        {},
        10**500,
    ],
)
def test_invalid_base_score(payload, metric, value):
    metric["cvssData"]["baseScore"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("field", ["version", "vectorString", "source"])
@pytest.mark.parametrize("value", [None, "", " ", 31, False, [], {}])
def test_invalid_optional_score_strings(payload, metric, field, value):
    target = metric if field == "source" else metric["cvssData"]
    target[field] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("version", ["2.0", "3.0", "4.0", " 3.1 "])
def test_wrong_version(payload, metric, version):
    metric["cvssData"]["version"] = version
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_absent_optional_score_fields(payload, metric):
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["decision"] == "review"
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["score_source"] is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        "",
        [None],
        [{}],
        [{"lang": "en"}],
        [{"value": "text"}],
        [{"lang": 1, "value": "x"}],
        [{"lang": "en", "value": None}],
    ],
)
def test_invalid_descriptions(payload, cve, value):
    cve["descriptions"] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("mode", ["absent", "empty", "non_english", "blank"])
def test_no_english_description(payload, cve, mode):
    if mode == "absent":
        del cve["descriptions"]
    else:
        cve["descriptions"] = {
            "empty": [],
            "non_english": [{"lang": "uk", "value": "Опис"}],
            "blank": [{"lang": "en", "value": " "}],
        }[mode]
    assert extract_record(payload, CVE_ID)["description"] is None


def test_first_nonempty_english_description(payload, cve):
    cve["descriptions"] = [
        {"lang": "uk", "value": "Опис"},
        {"lang": "en", "value": ""},
        {"lang": "en", "value": "First"},
        {"lang": "en", "value": "Second"},
    ]
    assert extract_record(payload, CVE_ID)["description"] == "First"
    cve["descriptions"].append({"lang": "en", "value": None})
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_first_primary_over_secondary(payload, cve, metric):
    secondary = deepcopy(metric)
    secondary.update(type="Secondary", source="secondary@example.invalid")
    secondary["cvssData"].update(baseScore=7.9, attackComplexity="HIGH")
    later_primary = deepcopy(secondary)
    later_primary["type"] = "Primary"
    cve["metrics"]["cvssMetricV31"] = [secondary, metric, later_primary]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["score"] == 9.8
    assert report["observed"] == "LOW"
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "review"


def test_first_without_primary(payload, cve, metric):
    first = deepcopy(metric)
    first["type"] = "Secondary"
    first["cvssData"].update(baseScore=8.0, attackComplexity="HIGH")
    metric.pop("type")
    cve["metrics"]["cvssMetricV31"] = [first, metric]
    report = build_report(extract_record(payload, CVE_ID), CVE_ID, 2)
    assert report["score"] == 8.0
    assert report["observed"] == "HIGH"
    assert report["decision"] == "other"


@pytest.mark.parametrize(
    "first_score, first_complexity, second_score, second_complexity",
    [(9.8, "HIGH", 7.9, "LOW"), (7.9, "LOW", 9.8, "HIGH")],
)
def test_never_combine_sources(
    payload, cve, metric, first_score, first_complexity, second_score, second_complexity
):
    first = deepcopy(metric)
    first["type"] = "Primary"
    first["cvssData"].update(baseScore=first_score, attackComplexity=first_complexity)
    metric["type"] = "Secondary"
    metric["cvssData"].update(
        baseScore=second_score, attackComplexity=second_complexity
    )
    cve["metrics"]["cvssMetricV31"] = [first, metric]
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, 2)["decision"] == "other"
    )


def test_selected_missing_field_not_filled_from_other_source(payload, cve, metric):
    secondary = deepcopy(metric)
    secondary["type"] = "Secondary"
    del metric["cvssData"]["attackComplexity"]
    cve["metrics"]["cvssMetricV31"] = [secondary, metric]
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, 2)["decision"]
        == "insufficient_data"
    )


def test_unselected_scores_not_validated(payload, cve, metric):
    cve["metrics"]["cvssMetricV31"] = [
        {"type": "Secondary", "cvssData": None, "source": None},
        metric,
        {"type": "Primary", "cvssData": {"baseScore": False}},
    ]
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, 2)["decision"] == "review"
    )


def test_unselected_entries_still_must_be_objects(payload, cve, metric):
    cve["metrics"]["cvssMetricV31"] = [metric, None]
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_irrelevant_fields_ignored(payload, metric):
    metric["cvssData"]["attackVector"] = None
    metric["unused"] = None
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, 2)["decision"] == "review"
    )


@pytest.mark.parametrize("variant", [True, False, 0, 16, -1, "2", 2.0, None])
def test_invalid_variants(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, variant)


@pytest.mark.parametrize(
    "variant, decision",
    [
        (1, "review"),
        (2, "review"),
        (3, "review"),
        (4, "review"),
        (5, "review"),
        (6, "review"),
        (7, "review"),
        (8, "other"),
        (9, "other"),
        (10, "other"),
        (11, "other"),
        (12, "other"),
        (13, "other"),
        (14, "other"),
        (15, "other"),
    ],
)
def test_valid_variant_contract(payload, variant, decision):
    assert (
        build_report(extract_record(payload, CVE_ID), CVE_ID, variant)["decision"]
        == decision
    )


def test_report_rule_is_independent(payload):
    record = extract_record(payload, CVE_ID)
    first = build_report(record, CVE_ID, 2)
    first["rule"]["threshold"] = 0
    assert build_report(record, CVE_ID, 2)["rule"]["threshold"] == 8.0
