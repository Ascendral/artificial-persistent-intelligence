# CORD Anchor Service

The server side of CORD's zero-knowledge anchoring (see
[`docs/ANCHORING_PROTOCOL.md`](../docs/ANCHORING_PROTOCOL.md)). It receives
signed chain-head batches (~300 bytes, **never log payloads**), enforces
sequence continuity, and countersigns each accepted anchor with a trusted
timestamp. That countersignature is what lets a third party trust the audit
trail's integrity without ever seeing the customer's code.

## What's proven vs. what's deploy-pending

**Proven — `logic.test.js`, 9 tests, real Ed25519, in-memory store:**
- enrollment + signature verification (unknown client / bad sig rejected)
- seq + `prev_anchor_head` continuity → replay, gaps, and forged prev-heads
  become `CONFLICT`, quarantined, never overwritten
- countersigned receipts that the client verifies (`verifyReceipt`)
- **Web Crypto interop** — a `node:crypto`-signed client batch verifies under
  the Worker's actual `crypto.subtle` Ed25519 path, and its receipt verifies
  back in `node:crypto`
- the **full client → server → verify loop**, including a regenerated
  internally-valid log that gets caught (`head_mismatch`)

`logic.js` is dependency-injected (store + crypto), so the code under test is
byte-for-byte the code the Worker runs.

**Deploy-pending — needs your Cloudflare account (not exercised by `npm test`):**
- `worker.js` (HTTP routing) and the D1-backed store run only in the Workers
  runtime. Verify them with `wrangler dev` before relying on them.

## Layout

| file | role |
|---|---|
| `logic.js` | protocol logic (pure, injected) — the tested core |
| `crypto-node.js` | Ed25519 via `node:crypto` (tests / Node hosts) |
| `crypto-web.js` | Ed25519 via Web Crypto (the Worker) |
| `memory-store.js` | in-memory store (tests / local dev) |
| `worker.js` | Cloudflare Worker entry (HTTP + D1) |
| `schema.sql` | D1 tables |
| `wrangler.toml` | Worker + D1 config |
| `gen-server-key.js` | one-time server keypair generator |

## Deploy

```bash
# 1. server keypair
node anchor-service/gen-server-key.js

# 2. D1 database (put the printed id into wrangler.toml)
wrangler d1 create cord-anchors
wrangler d1 execute cord-anchors --file=anchor-service/schema.sql

# 3. secrets
wrangler secret put SERVER_PRIVATE_KEY_PEM
wrangler secret put SERVER_PUBLIC_KEY_PEM

# 4. deploy
wrangler deploy
```

## Endpoints

| method | path | body / result |
|---|---|---|
| POST | `/enroll` | `{ clientId, publicKeyPem }` → `{ status }` |
| POST | `/anchor` | signed batch → `{ status, receipt? }` (200 / 409 conflict / 400) |
| GET | `/anchors/:logId` | `{ anchors[] }` (consumed by `cord-engine verify`) |
| GET | `/pubkey` | `{ server_public_key }` (to verify receipts offline) |

## Not in v1 (honest scope)

- `appendLog` auto-emit of anchors on the client (manual `createAnchor` for now)
- encrypted-log verification
- key rotation succession chains
- Sigstore/Rekor cross-posting
