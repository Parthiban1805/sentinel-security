# sentinel/assistant: AI investigation assistant (v0.6, ADR-0014)

Explains one incident with Claude. Never changes state. Off unless `--ai` is given.

## Network destination (project rule 5)
| Module | Destination | Auth | Sends | Receives |
|---|---|---|---|---|
| `client.py` | `https://api.anthropic.com` (fixed in code; `ANTHROPIC_BASE_URL` is ignored) | Anthropic API key from the OS credential store (`keyring`, service `sentinel-assistant`); never env vars or files | System prompt, plus the disguised evidence pack from `pack.py` (placeholders, rule text, times, severities, asset type and importance) | JSON in a fixed schema: summary, impact, unknowns, read-only steps, report draft |
| `nvidia.py` (ADR-0015, `provider = "nvidia"`) | `https://integrate.api.nvidia.com/v1/chat/completions` (fixed in code; HTTPS, no redirects, proxy and certificate environment variables ignored) | NVIDIA API key from the OS credential store (entry `nvidia-api-key`); never env vars or files | The same system prompt and disguised evidence pack, plus the JSON schema as text | A chat completion whose text must pass the same JSON schema; refused otherwise |

No tools are offered to the model. There are no automatic retries (one confirmed call is one billed
request), and the timeout is 120 s. `--ai` refuses to run without an interactive terminal, and there is no `--yes`.

## Flow
1. `pack.py` builds the allow-listed, disguised pack. It refuses if anything identifying, credential-shaped
   or placeholder-shaped remains.
2. `budget.py` checks the daily call cap and the monthly budget.
3. The operator confirms the destination, model and worst-case cost.
4. `budget.py` reserves the worst case in the ledger.
5. `client.py` sends one request.
6. `budget.py` settles the ledger to the actual cost (a failed call keeps its reservation).
7. `output.py` validates the schema, strips URLs, markup and control characters, and drops response-action
   steps and checks that would open secret-bearing files. It prints the record's own sections (facts, reach,
   plan state, whether the incident can close) itself, so the model never writes facts, and heads every
   model-written section "AI". It swaps names back locally as inline code, and refuses credential-shaped output.

The result goes to `<home>/ai-summaries/<ID>.ai-summary.md`.

## Commands
```
sentinel incident summary <ID> --dry-run     # print exactly what would be sent; sends nothing
sentinel incident summary <ID> --ai          # ask, then send (interactive terminal only); --deep for the larger model
sentinel ai set-key | delete-key | usage
```

## Settings (`[assistant]` in sentinel.toml)
`model` (default `claude-sonnet-5-5`), `deep_model` (`claude-opus-5-5`), `max_output_tokens` (8000),
`daily_calls` (30), `monthly_usd` (20), `fallbacks` (true).

Tests (`tests/sentinel/test_assistant.py`) use a fake client and never touch the network.
