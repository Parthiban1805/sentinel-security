# ADR-0026: Sandbox egress allow-list through a proxy container (v0.7f item 4)
Date: 2026-11-10 | Status: proposed (needs human review) | Amends: ADR-0017 (Docker sandbox)

## Context
ADR-0017 runs agent code in a container with `--network none`. That blocks dependency installs and any test that
needs a package index, so the owner chose "no allow-list in this release, it needs a proxy container and its own
ADR" (option A). The product plan (v0.7d item 3) asks for that allow-list: allowed hosts only, DNS resolved by
the proxy, private, loopback, link-local and metadata addresses refused, plain-HTTP method and path rules, no TLS
interception, and each refusal recorded as an `egress_anomaly` event (the first real producer of that type).

Threats this addresses (labelled; none observed here): code run by an agent sending data to a host the owner did
not choose; reaching the cloud metadata service or the local network from the container (SSRF-style); exfiltration
through DNS lookups of attacker names; DNS rebinding (an allowed name that later resolves to an internal address).

## Decision
1. **Off by default.** `sentinel sandbox run` keeps `--network none`. `--allow-net` opts in, and needs a
   `[sandbox.egress]` table in `sentinel.toml` (agents cannot write that file, ADR-0017):
   - `allow = ["pypi.org", "*.pythonhosted.org", "host:8443"]`: HTTPS through `CONNECT`, port 443 unless given;
     `*.suffix` covers subdomains, not the bare name, and needs two labels after the `*`.
   - `http = ["GET,HEAD deb.debian.org /debian/"]`: plain HTTP on port 80, GET and HEAD only, a path prefix.
   - Refused when written: IP addresses, single-label names, `*.com`-style wildcards, `.internal`, `.local`,
     `.localhost`, `.arpa`, `metadata.google.internal`, path prefixes with `.`/`..` segments or encoded dots and
     slashes, more than 100 rules. The proxy re-checks the same rules when it starts.
2. **Topology, per run** (labelled `sentinel.sandbox=1`, all removed afterwards):
   - `<run>-in`: a Docker network created with `--internal` (no route out). The sandbox container joins only this
     one, with `--dns 192.0.2.1` (TEST-NET-1) so external names have no working upstream, and `HTTP(S)_PROXY`
     pointing at `http://egress-proxy:3128`.
   - `<run>-out`: an ordinary bridge network with only the proxy on it; nothing else can reach the proxy from there.
   - The proxy container joins both, under the alias `egress-proxy` on the internal one.
3. **The proxy** (`sentinel/egressproxy.py`, stdlib only, ~400 lines) runs from the SAME pinned sandbox image
   (`python3 -I`), mounted read-only with its JSON config. No new image to pin or trust. Same hardening as the
   sandbox: read-only root, all capabilities dropped, `no-new-privileges`, uid 65534, memory, CPU and process limits.
   - **HTTPS:** `CONNECT` to an allowed host and port, then a byte tunnel. The proxy does not decrypt TLS.
   - **HTTP:** absolute-form GET or HEAD without a body, matched on host, method and path prefix. It is sent on with
     the checked Host header, without proxy or hop-by-hop headers, `Connection: close`, one request per connection
     (later bytes from the client are never forwarded).
   - **DNS:** only a name that passed the rules is resolved, by the proxy. Every answer must be a public address;
     one private, loopback, link-local, shared (100.64/10), reserved, multicast or documentation answer refuses the
     name (`internal_address`); the metadata addresses (169.254.169.254, 169.254.170.2, 100.100.100.200,
     fd00:ec2::254) give `metadata_address`. IPv4-mapped, NAT64, 6to4 and Teredo forms are unwrapped first. The
     proxy connects to the vetted address, never re-resolving (rebinding).
   - **IP literals** as targets, `https://` absolute-form, request bodies, other methods and malformed heads are
     refused. At most 64 connections, 16 KiB heads, 30 s to send a head, 120 s idle.
   - **Log:** one JSON line per decision on stdout, capped at 5,000 lines (`log_cut`).
4. **Events.** After the run, Sentinel reads the proxy's log, then removes the proxy and both networks. Each refusal
   is one `egress_anomaly` (source `sandbox_proxy`, asset: the project's agent, confidence high: the proxy saw it),
   up to 50 per run plus one summary. Severity: metadata target high, internal target medium, the rest low.
   **Refused host names are never stored whole** (a name the code asked for can carry data in any label it
   chose, rule 1). Under a domain the owner allowed, the domain is kept; otherwise only `h-<hash of the second
   label>.<tld>`. A SHA-256 prefix of the whole name is kept for grouping. A public IP literal is stored as
   `[public address]`; an internal or metadata address is kept.
   What the code meant is not known; any incident built on these events states intent as a hypothesis (rule 6).
5. **Gateway (patch):** `sandbox run --allow-net` asks first when the agent runs it (BG-30). An allowed host can
   receive data in an HTTPS body, which the proxy cannot see, so a person confirms each networked run.
6. **Network destinations (rule 5):** this code makes no call of its own. The proxy connects only to the hosts the
   owner lists in `[sandbox.egress]`, on behalf of the sandboxed command, and only during `--allow-net` runs.
   This ADR and `sentinel.example.toml` document that.

7. **Security review fixes (2026-11-10, `security-reviewer`, verdict "block" before these):**
   - **C1:** only a target that parses as an IP address is an `ip_literal` refusal, and only an internal or
     metadata address is kept in the event. A name that only looks numeric (`<x>.0`, `[<x>]`) is a bad request
     recorded without its host.
   - **C2:** the CLI refuses abbreviated options everywhere (argparse took `--allow` for `--allow-net`). BG-30 checks
     shell words with quotes and escapes removed, and any `--al...` option.
   - **M1:** plain-HTTP rules apply to port 80 only (`port_not_allowed`).
   - **M2:** any control character in the head except tab, including a bare CR or LF, is a bad request (no
     smuggled second request), and every `Content-Length` copy is checked.
   - **M3:** metadata, internal and IP-literal refusals have their own log budget past the 5,000-line cap; events
     list the most severe refusals first; a cut log makes the summary at least medium.
   - **Minor fixes:**
     - a refused name outside the allowed domains is kept only as `h-<hash of its second label>.<tld>`;
     - malformed names are refused before DNS;
     - the proxy's process limit is 256 and its open files are capped;
     - the whole head has one 30 s deadline;
     - allowed and error log lines carry no host;
     - HTTP path prefixes must end with `/`.
   - **Live check added:** `host.docker.internal` and the internal network's gateway are unreachable from the
     sandbox (passed on Docker Desktop, Docker 29.2.0). On a Linux Docker engine this is not verified yet.

## Consequences (security, operations, cost)
- **Security:**
  - Sandboxed code reaches only listed hosts; the metadata service, the LAN, the Docker host and unlisted names are
    refused, and unlisted names are never looked up by the proxy.
  - Log lines and events never hold a whole refused host name; allowed connections are logged without one.
  - Fails closed: a bad rule refuses the run; a proxy that does not report ready within ~10 s (for example an image
    without `python3`) stops the run before the sandbox starts; any start failure removes what was created.
  - **Not a boundary / known limits:**
    - **Data can leave to an allowed host.** An HTTPS POST to an allowed host (for example a code host that accepts
      uploads) is invisible without TLS interception, which this ADR rules out. List only hosts you would let the
      code send data to; BG-30 makes the agent ask.
    - **Domain fronting:** the TLS SNI and HTTP Host inside the tunnel are not checked; on a shared CDN an allowed
      name's address can serve other sites.
    - **DNS from the sandbox:** Docker's embedded DNS answers container names on the internal network. Whether it
      forwards external names from an `--internal` network differs by Docker version; `--dns 192.0.2.1` is set so
      a forwarded query has no working upstream. **Verified live 2026-11-10 on Docker Desktop (Docker 29.2.0):**
      `example.com` did not resolve inside the sandbox (`gaierror`). Other Docker versions are not verified; the
      live test (`test_live_egress_proxy_allows_only_listed_hosts`) checks it.
    - **Live result 2026-11-10 (same machine):** pypi.org (allowed) returned 200 through the proxy; example.com was
      refused (`host_not_allowed`); `http://169.254.169.254/` got 403 (`ip_literal`, target metadata); a direct
      connection to 1.1.1.1:443 had no route; no sandbox container or network was left afterwards.
    - Docker Desktop's own networking (host.docker.internal, its VM) is outside this design; the internal network
      has no route to it, which the live test checks only indirectly (direct connections refused).
    - Refused names under an allowed domain keep that domain; all others keep only a hash of their second label
      and the last label, so code-chosen labels are not stored.
- **Operations:**
  - Docker Desktop must allow user-defined networks (default). `sentinel sandbox check` prints the rule count.
  - A failed cleanup is reported with `docker ps -a --filter label=sentinel.sandbox=1`.
  - The owner applies the gateway patch (BG-30) and re-pins the hooks.
- **Cost:** none in money. Each networked run creates two networks and one extra container (about a second).

## Alternatives considered
- **Squid, tinyproxy or Envoy as the proxy:** mature, but a second image to pin and pull, a config language to
  generate safely, and none refuses internal resolved addresses out of the box without extra ACL work. Reusing the
  pinned sandbox image keeps the supply chain unchanged. Revisit for the v0.8 endpoint agent.
- **iptables rules on the host or in the container:** needs `NET_ADMIN` or host changes (rule 4: firewall changes
  need approval), and Docker Desktop on Windows hides the VM's firewall.
- **TLS interception (a local CA):** would let the proxy see request bodies and paths, but puts a CA key on the
  machine and breaks certificate pinning; ruled out in the product plan.
- **Allowing `--network bridge` with a host list:** no enforcement point; the code could reach any address.
