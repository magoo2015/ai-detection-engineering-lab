import pytest

from evaluation.metrics import calculate_metrics


def _result(classification):
    return {
        "scenario_id": f"s-{classification}",
        "classification": classification,
    }


def test_calculate_metrics_aggregates_counts_and_rates():
    results = [
        _result("TP"),
        _result("TP"),
        _result("FP"),
        _result("FP"),
        _result("TN"),
        _result("FN"),
        _result("FN"),
        {"scenario_id": "limitation", "classification": None},
    ]

    metrics = calculate_metrics(results)

    assert metrics["tp"] == 2
    assert metrics["fp"] == 2
    assert metrics["tn"] == 1
    assert metrics["fn"] == 2
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["false_positive_rate"] == 2 / 3
    assert metrics["f1"] == 0.5


def test_precision_undefined_when_no_predicted_positives():
    metrics = calculate_metrics([_result("TN"), _result("FN")])

    assert metrics["tp"] == 0
    assert metrics["fp"] == 0
    assert metrics["precision"] is None


def test_recall_undefined_when_no_actual_positives():
    metrics = calculate_metrics([_result("TN"), _result("FP")])

    assert metrics["tp"] == 0
    assert metrics["fn"] == 0
    assert metrics["recall"] is None


def test_false_positive_rate_undefined_when_no_actual_negatives():
    metrics = calculate_metrics([_result("TP"), _result("FN")])

    assert metrics["fp"] == 0
    assert metrics["tn"] == 0
    assert metrics["false_positive_rate"] is None


def test_f1_undefined_when_precision_or_recall_undefined():
    metrics = calculate_metrics([_result("TN")])

    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["f1"] is None


def test_f1_undefined_when_precision_and_recall_are_zero():
    # Precision and recall can both be 0 when TP=0 with FP>0 and FN>0.
    metrics = calculate_metrics([_result("FP"), _result("FN")])

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] is None


def test_limitation_results_do_not_affect_counts():
    metrics = calculate_metrics(
        [
            _result("TP"),
            {"scenario_id": "lim", "classification": None},
        ]
    )

    assert metrics["tp"] == 1
    assert metrics["fp"] == 0
    assert metrics["tn"] == 0
    assert metrics["fn"] == 0


def test_unsupported_classification_is_rejected():
    with pytest.raises(ValueError, match="UNKNOWN"):
        calculate_metrics([_result("TP"), _result("UNKNOWN")])
