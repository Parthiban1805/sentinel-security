# ADR-0015: NVIDIA hosted API as a second provider for the AI assistant
Date: 2026-11-02 | Status: accepted (owner, 2026-11-02, by instruction to the agent)

## Context
ADR-0014 chose the Claude API for the v0.6 assistant. The owner asked on 2026-11-02 to use NVIDIA's hosted
OpenAI-compatible API "for now, instead of the Anthropic API", and gave the endpoint and model from NVIDIA's
sample code. No Anthropic key exists yet, so this lets the first live call and the exit-gate scoring proceed.

**"Local" needs care.** `integrate.api.nvidia.com` is NVIDIA's cloud service. It is not a model on this
machine, so incident data still leaves the machine. A model on the owner's own hardware would need a new ADR
(loopback destination); the provider structure below makes that a small change.

## Decision
1. **A `provider` setting.** `[assistant] provider = "anthropic" | "nvidia"`, default `anthropic`
   (ADR-0014 is unchanged). The command, confirmation, budget, evidence pack, output checks and files are the
   same for both providers.
2. **Destination: `https://integrate.api.nvidia.com/v1/chat/completions`, only.** Fixed in code
   (`sentinel/assistant/nvidia.py`). HTTPS only, default port, redirects refused (so the key is never forwarded
   elsewhere), proxy and certificate environment variables ignored, certificates verified with the OS store as
   for the collectors. Standard library only (`urllib`): no new package.
3. **Key storage.** Same rules as ADR-0014: only the OS credential store (service `sentinel-assistant`, entry
   `nvidia-api-key`), set with `sentinel ai set-key --provider nvidia` (hidden input). Never an environment
   variable, config file or `.env`, and never printed. A stored key with spaces or line breaks is refused
   (header safety). The repr of the API object hides the key.
4. **What is sent.** Exactly the disguised evidence pack of ADR-0014 and the same system prompt. Nothing
   provider-specific is added to the data. `--dry-run` shows the pack for either provider.
5. **No tools; schema-checked answer.** This API does not enforce a JSON schema as the Claude API does here, so
   the schema is given in the prompt and the answer is extracted (a `<think>` block or Markdown fence is
   dropped) and then validated locally against the same schema. A malformed answer is refused and nothing is
   written. All the output checks of ADR-0014 (URL and markup removal, control characters, action-step filter,
   credential guard, AI label) apply unchanged.
6. **Settings chosen.** Non-streaming; temperature 0.2 and top-p 0.95 (steady, repeatable answers, rather than
   the 1.0 of the sample); reasoning switched off (`enable_thinking: false`) so thinking text does not use the
   output allowance. The `fallbacks` setting is a Claude-only feature and is ignored. The model id may be any
   id of a plain, safe shape; the default is the id from the owner's sample. Sentinel has not confirmed that
   this model exists or what it can do.
7. **Budget.** Calls are reserved before they are sent and count even if they fail, as in ADR-0014. The owner
   states that this NVIDIA API is **free** (2026-11-02; not verified by Sentinel), so the default model is priced
   at $0 and answer files say so. Any other NVIDIA model id keeps the ADR-0014 rule: unknown models are priced at
   the highest known tier. The Claude refusal-fallback price is not applied to NVIDIA. The **daily call cap** is
   the working limit for this provider; NVIDIA may still apply its own rate or credit limits, and its portal shows
   the real use.

## Consequences (security, operations, cost)
- **New outbound destination:** `integrate.api.nvidia.com` receives the disguised pack (rule ids, times,
  severities, Sentinel's own rule text, placeholders, asset type and importance).
- **Terms reviewed 2026-11-02 (agent-read, owner to confirm).** Source: NVIDIA API Trial Terms of Service, PDF at
  `assets.ngc.nvidia.com/products/api-catalog/legal/NVIDIA API Trial Terms of Service.pdf` (file dated 2025-10-07).
  - §1.2 and §1.4: trial only. Without a paid Subscription, use is "only... for internal testing and evaluation
    purposes, not in production". The "free" use is trial credits.
  - §2.3: content is not stored at the end of a session, except §2.4 (fine-tuning services).
  - §3.3: NVIDIA "will collect... User Content and Generated Content to improve NVIDIA products and services,
    including AI models" (without identifying specific users). Use is logged for security, fraud and abuse
    monitoring and shared with third-party service providers.
  - §2.6 and §4.3: no confidential information or personal data.
  - §2.7: NVIDIA may monitor, scan or review content.
- **Decision from that review: the NVIDIA provider is for simulated incidents only, enforced in code.**
  `explain.run` refuses any incident that is not `is_test` when `provider = "nvidia"`, before the confirmation and
  before any call (tested). Real incidents need the Claude provider, or an NVIDIA paid Subscription and a new ADR.
- The exit gate is **per provider**. Scores for NVIDIA say nothing about Claude and the reverse. Use a new
  eval directory (`--dir`) when switching provider.
- If the API stops being free, or the owner's statement is wrong, the dollar figures are wrong. Check the
  portal, and change the price in `sentinel/assistant/budget.py`.
- Answer quality is unmeasured. A model that ignores "JSON only" will produce refused answers, not wrong ones.
- No Claude-specific protections apply here (server-side refusal fallback, structured-output enforcement).
- **Unverified until the first live call:** that the endpoint accepts `chat_template_kwargs`; the token usage
  field names; how the model formats its JSON; that the default model id is valid for the owner's account.
  Tests use a fake API.

## Alternatives considered
- **The `openai` Python package.** NVIDIA's sample uses it. It adds a dependency tree to pin and review for a
  single POST request; `urllib` with the existing TLS and no-redirect rules is smaller and already reviewed.
- **A model on this machine (for example Ollama or an NVIDIA container on `127.0.0.1`).** Nothing would leave
  the machine, which is the safest option for real incidents. Deferred to a new ADR when hardware and a model
  are chosen.
- **Streaming the answer** as in the sample. Not needed for a result that is parsed whole; reasoning text would
  also arrive in a separate field that Sentinel does not use.
- **Waiting for an Anthropic key.** Rejected by the owner for now.
