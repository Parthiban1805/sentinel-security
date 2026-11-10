# ADR-0025: Context firewall (v0.7d item 2)
Date: 2026-11-06 | Status: proposed (needs human review)

## Context
Sentinel stops the agent from reading credential files (gateway) and finds keys committed to Git (scanner). It did not
look at the data that leaves through the conversation: a prompt the user pastes a key into goes to the model
provider, and the agent can put a key, an email address or an internal URL into a WebFetch, a WebSearch or an MCP
call. The owner's ORE kernel has a "context firewall" for model requests; it is an idea source only (AGPL-3.0). Its
gaps are avoided: it counted matched rules rather than occurrences, missed newer key formats, matched card-like digits
with no checksum, missed link-local and metadata addresses, and logged to stdout only.

**Hook facts, checked in the official Claude Code hooks documentation on 2026-11-06** (code.claude.com/docs/en/hooks):
- `UserPromptSubmit` receives the prompt (pasted text expanded) and can block it. The reason is shown to the user,
  not to Claude.
  - It **cannot rewrite** the prompt.
  - **A blocked prompt is still written to Claude Code's local transcript**; `suppressOriginalPrompt` only keeps it
    out of the block message.
- `PreToolUse` can deny or ask, and can also rewrite the input (`updatedInput`).
- A hook that times out **does not block** the action (fail open), unless the hook is configured to block on failure.
- Hook input carries `agent_id` and `agent_type` inside sub-agents.

## Decision
- **One detector library,** `sentinel/contextfirewall.py`. It is stdlib only and Python 3.10-safe, and ships
  byte-identical to the gateway as `.claude/hooks/_firewall.py` (a test keeps the copies identical).
  - `scan(text)` reports **kinds and counts per occurrence, never the matched text**:
    - known credential formats: Google, GitHub classic and fine-grained, AWS, Stripe-style, `sk-` keys including
      `sk-ant-` and `sk-proj-`, Slack, JWT;
    - `password=`/`token:`-style assignments;
    - high-entropy tokens (a guess);
    - PEM private keys;
    - emails;
    - card numbers that pass the Luhn checksum;
    - private, link-local, IPv6 unique-local and cloud-metadata addresses;
    - prompt-injection phrases.
  - Scanning is linear and capped at 1,000,000 characters, and a cut is reported.
- **Prompts** (new `UserPromptSubmit` hook, `prompt_guard.py`):
  - A prompt holding a credential in a known format, a password assignment or a private key is **blocked**, so it
    never reaches the model provider (FW-10).
  - The reason names the kinds and counts and tells the user to use a fingerprint and rotate the credential if it
    was real. The original text is kept out of the block message.
  - Guesses, PII, addresses and injection phrases are not blocked: it is the user's own text, and the gateway checks
    what leaves through tools.
  - An internal error lets the prompt through and records FW-99. Blocking every prompt on a bug would lock the user
    out, and this is a safety net, not a boundary.
- **Data-leaving tools** (a third gateway layer after the built-in rules and the manifest, which can only tighten):

  | Tool input holds | Decision | Rule |
  |---|---|---|
  | a known credential, password assignment or private key | deny | FW-01 |
  | the cloud-metadata address (WebFetch) | deny | FW-02 |
  | a high-entropy guess, an email, a card number or an internal/link-local address | ask | FW-03 |
  | more than the scan limit | ask | FW-04 |

  - **Tools checked:** WebFetch (`url`, `prompt`), WebSearch (`query` and the domain lists), and any MCP tool (its
    whole input as JSON).
  - **Fail closed:** an error in the firewall denies these tools (FW-99). Other tools are not affected.
  - **No rewriting:** the gateway denies or asks, so the user always sees why a call stopped. `updatedInput` exists
    but is not used.
- **Telemetry:** every block and refusal is recorded in the tamper-evident decision log (rule id and class, no
  values).
  - Prompt blocks use the decision `prompt_block` and are **not** turned into agent events. A user pasting a key is
    not the agent misbehaving, so it must not raise R5b or the session score.
  - Tool refusals become `agent_tool_denied` events like any gateway deny.
- **The AI assistant pack** uses the same detectors as an extra leak check before anything is sent. A pack holding
  secret, private-key, PII or address data is refused.

## Amendment after the 2026-11-06 security review ("Approve with fixes"; tests in `test_firewall_review.py`)
- **Confirmed and fixed, in the older `gateway.py`:** a valid but very deeply nested tool input made the gateway exit
  1. Claude Code treats exit 1 as non-blocking, so the call went through past every rule. It now denies (GW-98).
- **Hooks read raw UTF-8 bytes.** `python -I` ignores the UTF-8 mode settings, and the console code page must not
  decide how input is read. A non-ASCII payload was tested on 3.10 and was not reproduced as a bypass; the fix
  removes the dependency anyway. The prompt guard also records a parse failure (FW-99).
- **Password assignments are a guess:** tools ask, prompts are not blocked. A value must end at whitespace, a quote or
  the end of the line and hold a letter and a digit, so code such as `getpass.getpass()`, `os.getenv('X')`,
  `Optional[str]`, `${NAME}` and paths is not matched.
- **Tool input:** every string and key is scanned, one per line, so a key at the start of a line in MCP content is
  still found, and every field (such as WebFetch `offset`) is covered.
- **Known prefixes** must not follow a letter, digit or `_` (`risk-…`, `self_hf_…`).
- **Metadata addresses:**
  - Denied for **every** data-leaving tool (MCP fetch and browser servers run locally).
  - Also caught in URL hosts written in decimal, hex or octal, and as the hostnames `metadata` and `instance-data`.
  - **Out of scope:** DNS names that resolve to the metadata address (catching them would need a lookup).
- **Fewer false positives:**
  - `::`, `0.0.0.0` and the documentation address ranges are ignored.
  - Card numbers need a card prefix and length as well as the checksum, and a 13-digit epoch-millisecond timestamp
    is not a card.
- **Cost:** emails are found by locating each `@` first. Worst-case inputs per pattern are timed in tests.
- **Oversized input:**
  - The last 64 KB is scanned as well as the first 1 MB.
  - Every reason says when input was only partly scanned.
- **More formats:** PGP private keys, GitLab, Hugging Face, npm and PyPI tokens.
- **Text cleanup before scanning:** Unicode is normalised (NFKC), zero-width and format characters are removed, and
  percent-encoding is decoded in place.
- **Pin and session score:**
  - `_manifest.py`, `_firewall.py` and `prompt_guard.py` are required hook files in the pin.
  - Firewall denials count as outbound attempts in the session score.
- **Still not closed (by design, accidents not exfiltration):** hex-encoded keys (entropy below the floor), keys
  split across lines or case-swapped, and DNS names for internal hosts. A user pasting a real key gets no rotation
  record, because the block is not an agent event; rotating is on the user.

## Consequences (security, operations, cost)
- **Security:**
  - Fewer credentials and less personal data reach the model provider or third-party MCP servers.
  - **Not a boundary:**
    - The prompt is still on disk in the transcript.
    - A hook timeout fails open.
    - Detectors are patterns and will miss unknown formats.
    - Content the agent reads from files is not filtered: the gateway blocks credential files, and the model sees
      what the agent reads.
    - Bash network tools are already denied by BG-01.
- **False positives:**
  - A tool call with an email address or an internal URL asks. The user confirms, nothing is silently dropped.
  - Prompts are blocked only on known formats and private keys.
- **Cost:** none. No network call, dependency or setting.

## Alternatives considered
- **Rewriting tool input with `updatedInput`:** quieter, but it would change what the agent asked for without anyone
  seeing it.
- **A proxy for Claude Code's own model traffic:** declined by the owner (2026-11-06). It intercepts the main tool's
  traffic and is fragile.
- **Blocking every high-entropy prompt:** it would block pasted hashes, base64 and logs.
