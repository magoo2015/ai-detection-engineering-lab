"""Aggregate detection quality metrics from evaluation results."""


def calculate_metrics(results):
    """Calculate TP/FP/TN/FN counts and derived rates.

    Only results with a non-None classification contribute to primary metrics
    (limitation scenarios are excluded). Any other non-None classification
    raises ValueError. Undefined ratios return None.
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for result in results:
        classification = result.get("classification")
        if classification is None:
            continue
        if classification == "TP":
            tp += 1
        elif classification == "FP":
            fp += 1
        elif classification == "TN":
            tn += 1
        elif classification == "FN":
            fn += 1
        else:
            raise ValueError(
                f"Unsupported classification {classification!r} for scenario "
                f"{result.get('scenario_id')!r}; expected one of TP, FP, TN, FN or None"
            )

    precision_denominator = tp + fp
    if precision_denominator == 0:
        precision = None
    else:
        precision = tp / precision_denominator

    recall_denominator = tp + fn
    if recall_denominator == 0:
        recall = None
    else:
        recall = tp / recall_denominator

    fpr_denominator = fp + tn
    if fpr_denominator == 0:
        false_positive_rate = None
    else:
        false_positive_rate = fp / fpr_denominator

    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "f1": f1,
    }
