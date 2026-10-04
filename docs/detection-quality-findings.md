# Detection Quality Findings

Findings from the Detection Quality Engineering phase for DET-SSH-001
(SSH Brute Force) and DET-SSH-002 (SSH Failures Followed by Success).

All numbers in this document come from a small, hand-built synthetic
scenario corpus in this lab. They describe how the current detector code
behaves against those scenarios. They are **not** production accuracy,
and they are not based on real environment telemetry.

## 1. Purpose of the evaluation framework

The framework in `evaluation/` measures how well each detection separates
malicious activity from benign activity, rather than whether the code runs.

- `evaluation/loader.py` loads and validates labeled scenarios from
  `evaluation/scenarios/det_ssh_001.yml` and `det_ssh_002.yml`.
- `evaluation/runner.py` runs each scenario's events through the unmodified
  detector (`detect_ssh_bruteforce` or `detect_ssh_compromise`) with its
  default configuration, then classifies the outcome as TP, FP, TN or FN
  using the scenario's `ground_truth` and whether any alert was produced.
- `evaluation/metrics.py` aggregates those classifications into precision,
  recall, false-positive rate and F1.

Each scenario also carries `expected_alert`, which records what the
current detector is *expected* to do. The runner reports this separately as
`behavior_matched`. A scenario can be an intended false negative: the
ground truth is malicious, the expected alert is `false`, and the behavior
matches.

Scenarios with `scope: limitation` are run and recorded, but they are
excluded from the primary metrics.

## 2. Regression testing vs. detection quality evaluation

| Question | Regression tests | Quality evaluation |
| --- | --- | --- |
| What is asked | Does the code still do what it did? | Is what it does useful? |
| Pass condition | Output matches the expected output | Outcome is scored against ground truth |
| Example | `tests/test_ssh_compromise.py` | `evaluation/scenarios/*.yml` |

Regression tests such as `tests/test_ssh_bruteforce.py`,
`tests/test_ssh_compromise.py` and
`tests/test_runtime_metadata_consistency.py` check that the detector logic
and its YAML metadata stay consistent. A detector can pass every
regression test and still miss real attacks or alert on benign activity.

Quality evaluation makes those gaps visible on purpose. The corpus contains
deliberate false negatives and false positives. Those scenarios still
"pass" (`behavior_matched` is true) because they document known detector
behavior. They count against the metrics because the outcome is wrong
relative to ground truth.

The test suite ties the two together:
`test_bundled_det_ssh_002_corpus_matches_expected_behavior` fails if
detector behavior drifts from the documented expectations. A change in a
quality metric therefore shows up as a test failure that has to be
reviewed.

## 3. DET-SSH-001 findings (SSH Brute Force)

The detector alerts when one `source_ip` produces at least 15 failed
authentications within 10 minutes. It does not use `username` or
authentication method.

| Scenario | Ground truth | Alert | Result | Finding |
| --- | --- | --- | --- | --- |
| S01 | malicious | yes | TP | 15 failures in 10 min, exactly at the threshold |
| S02 | malicious | yes | TP | 20 failures, above the threshold |
| S03 | malicious | no | FN | **Threshold-related FN:** 14 failures, one below the threshold |
| S04 | malicious | no | FN | **Low-and-slow FN:** 15 failures spaced 5 min apart, so no 15-event run fits in 10 min |
| S05 | benign | no | TN | Two legitimate mistyped passwords |
| S06 | benign | yes | FP | **Legitimate-admin FP:** an administrator mistypes a password 15 times |
| S07 | benign | yes | FP | **Stale-automation FP:** a deploy job retries with outdated credentials |
| S08 | malicious | no | excluded | **Distributed brute force:** multiple IPs, each below 15 failures |

S08 is a coverage limitation, not a tuning problem. Because DET-SSH-001
groups only by `source_ip`, a coordinated attack spread across many IPs is
structurally outside what this detection can see. It is reported but
excluded from the metrics. Counting it as an FN would mix "missed
within design" with "not designed to detect."

## 4. DET-SSH-002 findings (Failures Followed by Success)

The detector alerts when a successful authentication is preceded by at
least 3 failures from the same `source_ip` **and** the same `username`,
within the 10 minutes before the success. Events without a username are
never correlated. It does not consider `auth_method`.

| Scenario | Ground truth | Alert | Result | Finding |
| --- | --- | --- | --- | --- |
| S01 | malicious | yes | TP | 3 failures then success, exactly at the threshold |
| S02 | malicious | yes | TP | 5 failures then success |
| S03 | malicious | no | FN | **Threshold-related FN:** password guessed on the third attempt, so only 2 prior failures |
| S04 | malicious | no | FN | **Time-window FN:** success arrives 18–20 min after the failures |
| S05 | benign | yes | FP | A legitimate user mistypes 3 times and then succeeds |
| S06 | benign | no | TN | **Same-username protection:** failures for `admin`, success for `deploy` |
| S07 | benign | no | TN | **Same-source-IP protection:** failures and success for `admin` come from different IPs |
| S08 | benign | no | TN | **Missing-username protection:** an unknown username is never treated as a match |
| S09 | benign | no | TN | The success comes before the failures, so ordering is enforced |
| S10 | benign | yes | FP | **Auth-method challenge:** 3 password failures, then a successful public-key login |

S10 shows a real tradeoff. Falling back to an SSH key after forgotten
passwords does not indicate a guessed password. However, the detector
correlates across authentication methods and alerts anyway. The scenario
measures this analyst noise and does not change the detector.

## 5. Interpreting TP / FP / TN / FN

Classification uses ground truth and observed alerting only:

- **TP:** malicious, and the detector alerted.
- **FN:** malicious, and the detector stayed silent. This includes intended
  FNs such as DET-SSH-001 S03/S04 and DET-SSH-002 S03/S04.
- **FP:** benign, and the detector alerted. This includes intended FPs such
  as DET-SSH-001 S06/S07 and DET-SSH-002 S05/S10.
- **TN:** benign, and the detector stayed silent.
- **None:** a limitation scenario, excluded from the metrics.

Scoring is one outcome per scenario: did the scenario produce *any* alert?
Alert counts, alert quality and evidence content are not scored.

## 6. Metrics (synthetic controlled-corpus results)

These metrics are **synthetic evaluation results**. They are not
production performance.

| Detection | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DET-SSH-001 | 2 | 2 | 1 | 2 | 0.50 | 0.50 | ≈0.667 | 0.50 |
| DET-SSH-002 | 2 | 2 | 4 | 2 | 0.50 | 0.50 | ≈0.333 | 0.50 |

- Precision is TP / (TP + FP), recall is TP / (TP + FN), FPR is
  FP / (FP + TN), and F1 is the harmonic mean of precision and recall.
- DET-SSH-001 excludes the distributed brute-force limitation (S08) from
  these counts.
- DET-SSH-002 has a lower FPR only because its corpus contains more benign
  correlation-protection scenarios (S06–S09). This does not show it is
  "twice as good" as DET-SSH-001.

## 7. Why this corpus is not production accuracy

- **Tiny sample:** 7 scored scenarios for DET-SSH-001 and 10 for
  DET-SSH-002. A single scenario changes a metric by 10–30 points.
- **Constructed to probe edges:** scenarios were written to hit thresholds,
  windows and known FP sources, so the malicious-to-benign ratio and the
  difficulty mix are chosen, not observed.
- **No base rate:** real SSH telemetry is overwhelmingly benign. Production
  precision depends on alert volume against that base rate, which this
  corpus cannot represent.
- **Synthetic events:** clean, normalized fields with no parser errors,
  clock skew, missing logs, NAT or shared jump hosts.
- **Author bias:** the same project wrote the detectors and the scenarios.

Treat the numbers as a reproducible description of known behavior and a
baseline for detecting regressions. They are not an estimate of
real-world accuracy.

## 8. Known limitations and tradeoffs

**DET-SSH-001**

- Fixed per-IP volume threshold: lowering it catches S03-style attacks and
  makes S06/S07-style noise worse. Raising it does the reverse.
- The fixed 10-minute window misses low-and-slow attacks (S04).
- Grouping only by `source_ip` means distributed attacks are out of scope
  (S08). It also cannot tell spraying across many users from hammering one
  account.
- It cannot tell attackers apart from admins or stale automation (S06/S07)
  without context such as allowlists or asset ownership.

**DET-SSH-002**

- A 3-failure threshold misses attackers who guess quickly (S03) but flags
  ordinary mistyped passwords (S05).
- The 10-minute window misses a patient attacker who waits before using
  credentials (S04).
- Strict same-IP and same-username correlation reduces noise (S06–S08). It
  also means an attacker who rotates IPs, or fails on one account and
  succeeds on another, will not correlate.
- Ignoring `auth_method` produces FPs when a user falls back to key-based
  login (S10).

## 9. Why no tuning was performed

This phase aimed to measure the current detectors, not to optimize them.

- Tuning against the same 7–10 scenarios used to measure the detectors
  would overfit and inflate the metrics without proving any real
  improvement.
- Each candidate fix trades one error type for another (Section 8). Making
  that choice needs real alert volumes and analyst feedback, which this lab
  does not have.
- Keeping detector logic, thresholds and metadata unchanged gives a stable
  baseline, so future changes can be compared against documented behavior.

## 10. How a production team would evaluate this differently

A production Detection Engineering team would typically:

- **Replay real historical telemetry** to measure alert volume per day and
  per host, and use triage outcomes as labels instead of hand-written
  ground truth.
- **Measure analyst cost:** time to triage, escalation rate, and how many
  alerts are closed as benign. Precision is judged against SOC capacity.
- **Use adversary emulation or red-team exercises** to produce realistic
  malicious activity, including distributed, low-and-slow and
  credential-stuffing variants.
- **Hold out evaluation data** separate from data used for tuning, and
  re-run evaluations whenever thresholds change.
- **Add environmental context:** allowlists for scanners and automation,
  asset criticality, identity data and `auth_method`. Then evaluate those
  suppressions for the coverage they remove.
- **Track metrics over time** after deployment, because both attacker
  behavior and the benign baseline drift.
- **Evaluate detections as a layered set.** For example, DET-SSH-001 and
  DET-SSH-002 complement each other, and a separate detection could cover
  distributed attacks instead of stretching either one.
