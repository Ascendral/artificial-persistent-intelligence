/**
 * Canonical serialization for anchor batches and receipts.
 *
 * Pure, zero-dependency (no node:crypto, no fs) so it can be imported by
 * BOTH the client (cord/anchor.js, Node) and the anchor service
 * (anchor-service/worker.js, Cloudflare Workers — no fs available). Single
 * definition means client signing and server verification can never drift.
 */

// Deterministic, fixed key order, excludes `sig`. Signing and verification
// serialize identically so the signature is stable across runtimes.
function canonicalBatch(b) {
  return JSON.stringify({
    v: b.v,
    client_id: b.client_id,
    log_id: b.log_id,
    seq: b.seq,
    entry_count: b.entry_count,
    chain_head: b.chain_head,
    prev_anchor_head: b.prev_anchor_head,
    ts_client: b.ts_client,
  });
}

// The server countersigns over the client batch + its trusted timestamp.
function countersignData(batch, tsServer) {
  return canonicalBatch(batch) + "\n" + tsServer;
}

module.exports = { canonicalBatch, countersignData };
