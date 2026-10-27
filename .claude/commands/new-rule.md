---
description: Specify, implement and test a correlation rule
argument-hint: <rule id> <short description>
---

Add correlation rule: $ARGUMENTS

Use the correlation-rule-authoring skill. First write the rule spec into docs/spec/correlation-rules.md
and show it to me. After I approve, implement it in sentinel/correlation/ with tests (true positive,
true negative, near-miss outside window, test-event routing). Run ruff, mypy and pytest.
