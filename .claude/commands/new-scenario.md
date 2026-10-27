---
description: Create a scenario test case document and pytest skeleton
argument-hint: <scenario id, e.g. S7> <short description>
---

Create a scenario test for: $ARGUMENTS

Use the scenario-test-authoring skill. Copy docs/scenarios/TEMPLATE.md to docs/scenarios/<ID>-<slug>.md,
fill it from the catalogue in docs/scenarios/README.md, then delegate implementation of
tests/scenarios/test_<id>_<slug>.py to the scenario-tester subagent. Show me the test case before implementing.
