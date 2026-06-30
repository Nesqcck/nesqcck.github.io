---
layout: default
title: "The MCP Supply Chain's Real Blind Spot Isn't Malware — It's the Credentials You Hand to Closed Gateways"
---

# The MCP Supply Chain's Real Blind Spot Isn't Malware — It's the Credentials You Hand to Closed Gateways

*A read-only scan of ~34,000 MCP servers across five registries, and what it did and didn't find.*

---

> **TL;DR**
> I built **`mcp-registry-audit`**, a read-only scanner for two MCP supply-chain attacks — *rug-pulls* (a server turning malicious after approval) and *lookalikes* (brand impersonation) — and ran it across ~34,000 distinct server entries from five registries at a single 2026-06-29 snapshot. It found no source-readable malicious server. The more useful result is what it surfaced on the way: a large, growing class of **hosted aggregator gateways that route your real API keys through closed servers**. Their public connector code is clean pass-through; their credential handling is, by construction, invisible to static analysis. That gap — not malware in published code — is the part of the MCP supply chain current scanning can't see. The scanner is open-source: https://github.com/Nesqcck/mcp-registry-audit; the snapshot and per-registry coverage are below, so anyone can re-run it.

## Why I built this

The Model Context Protocol has a supply chain now: public registries listing thousands of servers an AI agent can install and grant access to. That makes it a target for the same attacks that hit npm and PyPI — and the official registry, by its own documentation, [does not screen server code](https://modelcontextprotocol.io/registry/about). Two are specific to how MCP works:

- **Rug-pull / drift** — a server is benign when you approve it, then a later version quietly adds an outbound call, a hardcoded exfil sink, or an install hook. The one confirmed real-world case is `postmark-mcp`: a clean connector that, in v1.0.16, began BCC-ing every email it sent to an attacker's address (disclosed by Koi Security (now part of Palo Alto Networks), September 2025).
- **Lookalike / brand impersonation** — a server named after a trusted brand (`stripe-mcp`, `notion-mcp`) published by someone who isn't that vendor, designed to be mistaken for official.

Other researchers have shown these attacks are *feasible*: OX Security demonstrated that most MCP registries will accept a malicious submission, and UpGuard showed the conditions for typosquatting are wide open (case-insensitive names, mostly-unverified publishers). I wanted to measure something they didn't: **not whether an attacker could get in, but whether malicious lookalikes and rug-pulls actually exist in the live ecosystem right now.**

## What the scanner does

Two pipelines, both **read-only**. They fetch public registry and package metadata over plain HTTP GET and score it. Nothing is ever installed, executed, or contacted; every URL, domain, or sink found in a package is treated as an inert string to be scored, never reached.

- **Rug-pull pipeline** diffs consecutive published versions of a server's source/manifest and scores newly-introduced signals: a new outbound call, a new hardcoded sink, an install hook, an env-harvest near a network call, a maintainer change, obfuscation.
- **Lookalike pipeline** matches server names against a canonical brand set (name distance + homoglyph + substring) and scores the surrounding evidence: publisher mismatch, install pointing off the canonical package, a fresh repo, a thin or fake contributor graph, an official-sounding name under a low-trust publisher.

Both produce ranked candidates, and **every score traces to a named signal with its evidence**. A human confirms or dismisses each by reading the source. That's how every finding here was confirmed: manually, from source, never by running anything.

It's built in Python (3.12+): metadata is fetched with httpx over GET only, parsed into pydantic models, and driven from a typer CLI; the lookalike pipeline uses rapidfuzz for name-distance scoring. The two pipelines are separate modules sharing one read-only fetch-and-cache core.

## What I swept

| Registry | Distinct servers | How instrumented |
|---|---|---|
| Glama | ~15,000 | source-level (repo/package available) |
| Official MCP Registry | ~14,133 | source-level |
| mcp.so | ~3,569 | name + publisher only (sitemap) |
| Smithery | ~1,446 | name + publisher only (brand-targeted search) |
| PulseMCP | ~205 | source-level |
| **Total** | **~34,353** | snapshot: 2026-06-29 |

Coverage is **uneven on purpose**, and it governs how to read everything below. Glama and the official registry (~85% of the total) expose repos and packages, so the detectors ran at full strength there. The two community registries — mcp.so and Smithery, where impersonation was most predicted to live — exposed only a name and a publisher per server (mcp.so has no clean structured data on detail pages; Smithery's unauthenticated catalog hard-caps enumeration), so only the weak signals could fire there. I did not aggregate these into one undifferentiated "scanned 34k" claim, and neither should anyone citing this.

## What I found

> Across the 2026-06-29 snapshot of ~34,353 distinct MCP server entries spanning the five registries above, neither detector fired on any server whose source I could read. I did not find a single live, source-readable malicious lookalike or rug-pull at snapshot time.
>
> This is an **absence-of-evidence result**, bounded by four limits: (1) the community registries were instrumented at name+publisher level only, so only weak signals could fire there; (2) Smithery's unauthenticated catalog caps enumeration; (3) mcp.so exposed only ~3,500 of its advertised ~20,000+ entries; (4) hosted closed gateways are not statically verifiable at all. What this demonstrates is that the most-vetted ~85% of the population contained **no readable malicious lookalike at snapshot** — not that the ecosystem is safe.

That distinction is the whole methodology. "I scanned and found nothing" is a weak claim on its own. A rug-pull, by definition, appears *after* approval — one snapshot can't catch future drift. And the registries where lookalikes were most likely to hide are exactly the ones I could only see at name level. Treat this as a prevalence upper-bound at a moment in time, published with the tool and the date so it can be re-run — not a clean bill of health.

What the sweep did establish: the registries are full of unofficial brand-named connectors — servers called after Stripe, Notion, GitHub, Slack, Postmark, Oura and others, published under non-vendor accounts. I resolved the strongest of these to source and read them. They were **legitimate-but-unofficial community connectors, not impersonation**: clean single-brand API clients, using the user's own token, no install hooks, no second destination. The detector flagging them was a true positive for "brand name under a non-canonical publisher" and a correct *dismissal* for malice. Telling those two apart is itself a useful result — and it pointed straight at the thing that can't be dismissed.

## The real blind spot: closed credential gateways

Reading the strongest brand-named candidates kept leading to the same architecture. They weren't standalone packages you install and run. They were thin front-ends for **hosted gateways** — you hand the gateway your real API key (your Stripe secret, your GitHub token), and the actual server logic runs on the provider's closed infrastructure.

This is now a whole class. Composio, Pipedream, Smithery's and Glama's hosting, and smaller players all market the same model, often as a feature: "centralized credential management," keys "encrypted at rest," "never exposed to the model." One concrete instance — `pipeworx-io` on GitHub — hosts on the order of 1,148 public connector repositories [NOTE: repo count confirmed on GitHub; the org's self-reported tool/source counts and creation date are marketing figures I could not independently verify, so I'm not citing them as fact], almost all thin, zero-star, templated wrappers that route through a single gateway endpoint. Its own README is explicit: credential handling happens server-side. You don't manage keys, the gateway does.

Here's the asymmetry, and it's the actual finding:

**The public connector code reads clean — and that tells you nothing about what the closed gateway does with your key.** Static analysis, the entire basis of supply-chain scanning, can confirm that the published code passes your token straight through to the brand's official API with no logging and no second destination. It cannot see what the gateway does *after* it receives that token: whether it logs it, retains it, forwards it, or honors its own marketing. "Clean by static analysis" is not "clean." It is "not statically falsifiable." For a credential-proxying hosted gateway, those are very different statements, and the gap between them is exactly where a supply-chain risk would live — invisible to every scanner, including mine.

This isn't an accusation against any specific provider; several are plainly legitimate businesses, and [OpenAI's own connector guidance](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) already tells users to do "due diligence" on aggregators and review how they handle data. It's a structural point: **the MCP ecosystem is rapidly normalizing a model where you grant production credentials to closed third-party servers that cannot be verified by the tools we use to verify everything else** — and almost no one is naming it as the distinct trust problem it is.

A related pattern worth flagging is how cheap this has become. OpenAPI-to-MCP generators let a provider mass-produce hundreds or thousands of branded connectors from API specs automatically — which is what lets a single org list 1,000+ brand-adjacent servers. Benign today, but it inflates registry counts, crowds discovery, and pre-stages brand-adjacent namespaces at scale. Worth watching as a future surface.

## What I think should change

- **Registries should label entries by provenance, and treat credential-proxying gateways as their own trust tier** — distinct from "official," "claimed," and "crawled." Granting your Stripe key to a hosted gateway is a categorically different trust decision than installing a local open-source server, and the listing should say so.
- **Publisher / namespace verification** ([reverse-DNS namespaces](https://modelcontextprotocol.io/registry/authentication), as the official registry is moving toward) closes most of the lookalike surface that currently relies on unverified names.
- **Behavioral screening and signing** would catch what static metadata can't — though even these stop at the gateway boundary.
- **Continuous re-scanning**, not one-time. A rug-pull appears after approval; a single snapshot (including this one) structurally can't catch it.

## How to reproduce this

The scanner is open-source: https://github.com/Nesqcck/mcp-registry-audit. The snapshot date (2026-06-29) and per-registry coverage are in the table above. The detection signals are documented in the repo, and every candidate score traces to its evidence. If you re-run it and find even one live malicious lookalike, that's a more important result than mine — please publish it.

A standing caveat on the numbers: registry totals across the MCP ecosystem are widely inflated and inconsistent (the official registry's metadata has been found to contain orders of magnitude more entries than unique underlying packages; mcp.so advertises far more than it enumerates; the major registries report divergent totals). Every count here is approximate and source-attributed, not ecosystem ground truth.

## Related work

This complements a fast-growing body of MCP security research. Here's where it sits, precisely:

- **Koi Security (now part of Palo Alto Networks)** found and disclosed `postmark-mcp`, the one confirmed real-world malicious MCP server (reactive, one incident). I swept proactively for the *class* and found no live instance at snapshot. Primary: [Koi disclosure](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft). Corroborating: [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html), [The Register](https://www.theregister.com/2025/09/29/postmark_mcp_server_code_hijacked/).
- **Invariant Labs** coined and tooled tool-poisoning and rug-pull detection — their tool **MCP-Scan**, which scans *your installed* servers. `mcp-registry-audit` scans the *registry population* instead. Source: [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (Beurer-Kellner & Fischer, 1 Apr 2025).
- **OX Security** and **UpGuard** showed malicious submission and typosquatting are *feasible*. My work measures *realized prevalence* — the companion question: given that attackers can get in, how many actually have? Sources: OX Security, [The Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) (15 Apr 2026); UpGuard, [Typosquatting in the MCP Ecosystem](https://www.upguard.com/blog/typosquatting-in-the-mcp-ecosystem) (Greg Pollock, 10 Apr 2026).
- Large-scale academic studies measure vulnerability and tool-poisoning *susceptibility*; none ran a brand-impersonation/rug-pull census with a negative result: [MCP at First Glance](https://arxiv.org/abs/2506.13538) (Hasan et al.), [MCPTox](https://arxiv.org/abs/2508.14925), and [MCP-Scanner](https://dl.acm.org/doi/10.1145/3786160.3788471) (Abadeh et al., EnCyCriS '26). Note: that **MCP-Scanner** is a separate academic paper — not Invariant's **MCP-Scan** above, and not `mcp-registry-audit`.

---

Nesqcck — Independent security researcher focused on AI agents, MCP, and software supply-chain integrity. Reverse engineering & detection tooling. The scanner is read-only and was used only against public metadata; no server was installed, executed, or contacted during this research.
