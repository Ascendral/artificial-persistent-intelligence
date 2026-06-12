# CORD Anchoring Protocol — v1 Spec

**Status: SPEC ONLY. Nothing in this document is implemented yet.**
**CORD = Counter-Operations & Risk Detection.**

## Problem

The CORD audit log (`cord/logger.js`) is a SHA-256 hash chain: each JSONL entry
carries `prev_hash` and `entry_hash = sha256(prev_hash + JSON.stringify(base))`,
rooted at the literal `"GENESIS"`. `verifyChain()` proves *internal consistency*
— but an attacker who controls the box doesn't tamper with the chain, they
**regenerate a clean fake chain from genesis**. A self-contained chain proves
nothing to a third party.

Anchoring fixes the trust root: the client periodically sends the current chain
head to an external anchor service, which countersigns it with a trusted
timestamp. History older than the last anchor can no longer be rewritten
without detection.

## Privacy guarantee (the product)

The anchor service receives **only**: a chain-head hash, a sequence number, a
log identity hash, and a signature — ~300 bytes. **No log payloads, ever.**
The service can verify integrity of an audit trail it cannot read. This is the
entire pitch: "we verify your audit trail without seeing your code."

## What this does NOT claim (read before marketing anything)

1. **Completeness.** CORD logs actions that go through CORD. An agent with raw
   shell access can act outside the gate. The claim is always "tamper-evident
   record of all *gated* actions," never "complete record of the agent."
2. **The pre-anchor window.** Entries written since the last anchor are still
   rewriteable. The window is bounded by the anchor interval, not zero.
3. **Pre-enrollment history.** A chain deleted before its first anchor never
   existed as far as the service knows.

## Client side (cord-engine)

### Keys
- `cord-engine anchor init` generates an Ed25519 keypair.
- Private key: `~/.cord/anchor.key`, mode `0600`, never leaves the machine.
- Public key registered with the anchor service at enrollment; service returns
  a `client_id`.
- Rotation: new keypair signed by the old key (`rotate` command); service
  stores the succession chain.

### Anchor batch (the only thing sent)

```json
{
  "v": 1,
  "client_id": "c_...",
  "log_id": "sha256 of (client_id + absolute log path + chain genesis time)",
  "seq": 42,
  "entry_count": 8170,
  "chain_head": "entry_hash of the most recent log entry",
  "prev_anchor_head": "chain_head of seq 41, or GENESIS",
  "ts_client": "ISO-8601",
  "sig": "ed25519 over the canonical JSON of all fields above"
}
```

- `seq` is strictly monotonic per `log_id`, persisted locally in
  `~/.cord/anchor.state.json`. A gap or repeat in `seq` at the service is a
  tamper alert, not an error to retry past.
- `prev_anchor_head` chains the anchors themselves — the service's record is
  also a chain, so neither side can drop an anchor silently.

### Trigger policy
Anchor on whichever comes first: every **N = 100 entries** or **T = 5 minutes**
(both configurable), plus always on graceful shutdown. Cost: one ~300-byte POST.

### Offline behavior
No network → batches queue locally (bounded, default 1000). Queued anchors are
sent in order on reconnect with their original `ts_client`; the service
timestamp will show the gap. **An anchor gap is reported as "unanchored
window," never silently healed.**

### Log rotation
Rotated logs start a new chain whose genesis entry embeds the final
`chain_head` of the previous file, and anchoring continues under the same
`log_id` with `seq` uninterrupted. (Requires a logger change: current
`getPrevHash()` returns `"GENESIS"` for any fresh file — that breaks chain
continuity across rotation and must be fixed as part of implementation.)

## Server side (anchor service)

Cloudflare Worker + R2/D1. Append-only. Per request:
1. Verify `sig` against the enrolled public key for `client_id`.
2. Verify `seq` is exactly `last_seq + 1` and `prev_anchor_head` matches the
   stored head for `seq - 1`. Mismatch → store the conflicting submission in a
   quarantine table and raise an alert; never overwrite.
3. Countersign: `server_sig = ed25519(server_key, client_batch + ts_server)`.
4. Return `{ seq, ts_server, server_sig }` — the client appends this receipt
   to `~/.cord/anchor.receipts.jsonl` (its proof if the service ever lies).

The service key's public half is published; receipts are verifiable offline.

## Verification: `npx cord-engine verify`

1. Walk the local chain (existing `verifyChain()` logic).
2. Load local receipts; fetch the service's anchor list for `log_id`.
3. For each anchor, recompute the chain head at `entry_count` entries and
   compare against the anchored `chain_head`.
4. Output, exactly one of:
   - `VERIFIED` — chain internally consistent and matches every anchor.
   - `TAMPERED` — chain rewritten relative to an anchored head (show which
     window).
   - `UNANCHORED WINDOW` — consistent but with gaps in anchor coverage (show
     time ranges).
   - `NO ANCHORS` — local-only chain; integrity is self-attested only.

The live sales demo is: tamper with one byte of an anchored log, run `verify`,
watch it name the window.

## Threats considered

| Attack | Defense |
|---|---|
| Regenerate clean chain from genesis | Heads anchored externally; recomputed head won't match |
| Truncate log tail | `entry_count` at each anchor exposes shrinkage |
| Drop anchors to shrink coverage | `seq` monotonicity + `prev_anchor_head` chaining |
| Anchor service rewrites history | Client-held countersigned receipts |
| Stolen client key, fake parallel chain | Quarantine on seq/head conflict — both submissions preserved, alert raised |
| Replay old batch | `seq` must be exactly last+1 |

Out of scope for v1: HSM key storage, multi-region service replication,
third-party transparency log cross-posting (Sigstore/Rekor interop is the
obvious v2 — our moat is the one-line integration and the compliance report,
not the cryptography).

## v1 implementation order

1. Logger: chain continuity across rotation (prerequisite, see above).
2. `anchor init` / keygen / state file in cord-engine.
3. Batch emit + queue in `appendLog()` path (config-gated, default off).
4. Worker service: enroll, submit, list endpoints.
5. `verify` command.
6. Tamper-demo script (becomes the landing-page demo).

Each step lands with tests that fail against the prior step's behavior —
same discipline as the d165634 regression tests.
