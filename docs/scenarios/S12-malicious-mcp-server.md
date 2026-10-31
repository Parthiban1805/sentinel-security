# S12: Agent uses a malicious or unapproved MCP server

- **Threat:** an MCP server that nobody reviewed (a typosquatted package, a server added by a compromised dependency, or one
  impersonating a trusted name) is called by the agent and can read what the agent sends or return injected instructions.
- **Priority:** 2
- **Preconditions:** the decision-log hooks are applied (they record every `mcp__<server>__<tool>` call as `allow_mcp`); at least one
  MCP server is approved in the inventory (`sentinel inventory agents`, then `sentinel inventory set mcp-<name> --actor <you> --approve`).
- **Simulated events (ordered):**
  1. One approved server exists in the inventory.
  2. The agent calls `read_file` on a server that is not approved (`sentinel.simulation.scenarios.unapproved_mcp`).
- **Expected detections:** `agent_tool_allowed` event with `attributes.mcp_server`; rule R5c.
- **Expected incident:** High, one per server (calls to the same server never open a second incident).
- **Expected response class:** approval required (approve or remove the server), investigate (what was sent), approval (rotate).
- **Pass criteria:**
  - [x] Unapproved server raises one R5c incident once allowlisting is on (`tests/sentinel/test_r5.py`, `test_agent_source.py`)
  - [x] No incident before any server is approved (allowlist mode off: every call would match, which is noise)
  - [x] Approved servers stay quiet; approval survives re-discovery
  - [x] Inventory keeps only name, transport, host and command basename; env values, headers and arguments are never stored
  - [ ] Demonstrated on a real session: not yet
- **Known gaps (facts):** servers configured at user scope are invisible (their configuration holds credentials and is off limits), so
  they always count as unapproved until registered by hand; claude.ai connectors also appear as servers; only the call is visible, not
  what was sent or returned (gateway, v0.7).
- **Metrics captured:** detection on simulated input = 1/1.
- **Cleanup:** temp state dirs removed by pytest.
