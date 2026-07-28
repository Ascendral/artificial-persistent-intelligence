# CORD demand test — 10 cold emails

Written 2026-07-27. Purpose: convert "nobody needs this" from a prediction into a measurement.

## Experiment design

**Hypothesis being tested:** nobody has this problem badly enough to pay for a solution.

**Falsification:** ≥2 of 10 replies describe the problem unprompted, or ask to see it.

**Kill condition:** ≥7 of 10 say "we already handle this" or don't reply within 14 days → stop building CORD. Archive it. Move on with evidence instead of a feeling.

Every email is written so that **"no" is the easy reply.** If the emails pitch, the data is garbage — people ghost pitches, and ghosting is ambiguous. A fast "nope, we're covered" is a *successful* outcome of this test.

## Baseline being measured against (2026-07-27)

- GitHub public since 2026-02-13: 4 stars (1 self), 0 forks, 0 issues, **2 views / 14 days**
- npm: 102 downloads/30d, flat trickle = mirror/scanner traffic, assume 0 real users
- Inbound inquiries to date: 0
- Cold outreach attempts to date: **0**

## Timing fact that makes this week non-arbitrary

EU AI Act (Reg. 2024/1689) **Article 12** — automatic event logging over the system lifetime,
min 6-month retention — enters **full application for high-risk AI systems on 2 August 2026**.
Penalties to €15M or 3% worldwide turnover. **No finalized technical standard exists yet**
(prEN 18229-1 and ISO/IEC DIS 24970 both still draft).

Obligation live + standard undefined = the window where teams buy tooling to cover themselves.
That window is open now and closes as the standards land.

## Competitive reality found while researching targets

These vendors are ALREADY publishing content on AI-generated-code audit trails / AIBOM:
Codacy, Apiiro, Bitloops, Axiom Studio, MergeLoom, MintMCP, Safeguard, Panto.

Read this correctly, both directions:
- **Against "nobody needs this":** eight companies are spending money betting the opposite.
- **Against "I'm early":** you are not early. You are late and unknown. They have content, funding
  and distribution; you have 2 page views. The gap is not product quality — it's that nobody
  knows the repo exists.

---

## The ten

Segments chosen so a "no" from each kills a different assumption.

### 1 — AI coding agent vendors (their buyers will demand this evidence)
**Subject:** are your enterprise buyers asking for agent audit logs yet?

You ship an agent that writes production code. On Aug 2 the EU AI Act's logging obligation
(Article 12) goes live for high-risk systems, and SOC 2 auditors have started asking clients to
attribute agent-authored commits to an accountable party.

Has a single enterprise buyer asked you for that evidence yet?

I'm asking because I built a tamper-evident audit log for agent actions and I'm trying to find
out whether the demand is real before I put another month into it. If the answer is "no, nobody
has ever asked" — that's the most useful reply you could send me. One line is plenty.

Alex Pinkevich

### 2 — AI coding agent vendors, security-questionnaire angle
**Subject:** what does your security questionnaire ask about code provenance?

Quick question from someone building in this space, not selling you anything today.

When enterprise prospects send you a security questionnaire, is there a line item about which
model generated which code, and who approved it? Or is that still not showing up?

I built an append-only hash-chained log for exactly that and I genuinely can't tell whether it
solves a real procurement blocker or a problem I invented. "Never comes up" is a completely
valid answer and the one I most need to hear if it's true.

Alex Pinkevich

### 3 — Regulated fintech/healthtech eng leadership
**Subject:** Copilot/Cursor in a SOC 2 environment — how are you evidencing it?

You're in a regulated environment and your engineers are almost certainly using AI assistants.

When your auditor asks "which of this code was AI-authored, by which model, and who reviewed
it" — do you have an answer today, or is that a problem you're planning to deal with later?

Not pitching. I built a tool for this and I'm testing whether the pain is real before I keep
going. If your auditor has never asked, please tell me that — it's the answer that saves me
the most time.

Alex Pinkevich

### 4 — Regulated industry, the "later" angle
**Subject:** the AI-code question your auditor hasn't asked yet

Genuine research question, 30 seconds.

Has an auditor, customer, or regulator ever asked your team to prove which parts of your
codebase were AI-generated?

If yes — what did you actually produce for them?
If no — do you expect that to change this year, or does it feel like noise?

I built an audit-trail tool on the assumption the answer is "yes, soon." Testing that assumption
before I invest more. Either answer helps.

Alex Pinkevich

### 5 — Compliance automation platforms (Vanta / Drata / Secureframe class)
**Subject:** are customers asking you for AI-code evidence collection?

You sit closer to this data than anyone: are your customers asking for evidence collection
around AI-generated code — AIBOM, model attribution, agent action logs — or is it not yet a
line item people request?

I've built an open-source engine that produces tamper-evident logs of AI agent actions
(hash-chained, Ed25519-anchored). Before I go further I want to know whether that's an
integration anyone would want, or a solution looking for a problem.

Straight answer appreciated, including "we don't see demand for that."

Alex Pinkevich

### 6 — SOC 2 / ISO audit firms
**Subject:** question from a builder: are clients struggling with AI-code attribution?

You're auditing companies whose code is increasingly AI-generated.

Are you actually asking clients about AI code provenance yet — and if so, are they able to
produce anything, or is everyone hand-waving?

I built tooling for this and I'd rather find out from an auditor than from my own assumptions
whether it matters. If it's not part of your testing yet and you don't expect it to be, please
say so plainly.

Alex Pinkevich

### 7 — EU-based providers of high-risk AI systems (Article 12 applies directly)
**Subject:** Article 12 logging — what are you doing before Aug 2?

Article 12 requires automatic event logging over the lifetime of a high-risk system, 6-month
minimum retention, and full application starts 2 August. There's still no finalized technical
standard (prEN 18229-1 and ISO/IEC 24970 are both draft).

How is your team covering that gap — building in-house, buying, or waiting for the standard?

I built an open-source hash-chained logging engine and I'm trying to learn whether teams want a
tool here or would never trust an outside one for compliance evidence. Honest answer either way
is useful.

Alex Pinkevich

### 8 — Adjacent vendors already publishing on this (Codacy / Apiiro / Bitloops class)
**Subject:** you're writing about AIBOM — is anyone buying yet?

I read your piece on AI-generated code and audit evidence. You're clearly betting this becomes a
real budget line.

Founder-to-founder: is it converting yet, or is it still content ahead of demand?

I've built an open-source engine in the adjacent slot — tamper-evident logs of agent actions
rather than static code scanning — and I'm deciding whether to keep going or shelve it. Your
read on whether buyers are actually showing up would settle it for me.

Happy to reciprocate with anything I learn.

Alex Pinkevich

### 9 — AI platform / infra teams running agents in production
**Subject:** when your agent does something wrong, can you reconstruct it?

If one of your agents took a destructive or out-of-policy action in production last month, could
you reconstruct exactly what it did, in an order you could prove wasn't edited after the fact?

That's the thing I built — an append-only hash-chained action log with cryptographic anchoring.

I'm trying to find out whether that's a problem teams actually feel, or one that only sounds
serious. If you'd just look at the CI logs and move on, tell me — that's a real answer.

Alex Pinkevich

### 10 — Design partner ask (for anyone from 1–9 who replies warm)
**Subject:** would you break this for me?

Following up — you said this is a real problem for you.

I'm not trying to sell you anything. I want one thing: 30 minutes where you try to use it and
tell me where it fails or where it doesn't fit how you actually work.

It's open source, zero dependencies, runs locally: github.com/Ascendral/artificial-persistent-intelligence

If it's useless for your case I'd rather learn that from you in 30 minutes than from six more
months of building alone.

Alex Pinkevich

---

## Tracking

| # | Segment | Sent | Reply | Verdict |
|---|---------|------|-------|---------|
| 1 | agent vendor / buyer demand | | | |
| 2 | agent vendor / questionnaire | | | |
| 3 | regulated eng leader | | | |
| 4 | regulated / "later" | | | |
| 5 | compliance platform | | | |
| 6 | audit firm | | | |
| 7 | EU high-risk provider | | | |
| 8 | adjacent vendor | | | |
| 9 | agent infra team | | | |
| 10 | design partner follow-up | | | |

Scoring date: 2026-08-10 (14 days).
Record the result here whatever it is. A dead table means the test wasn't run — not that the answer was no.
