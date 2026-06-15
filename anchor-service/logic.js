/**
 * Anchor service — protocol logic. Pure and dependency-injected (store +
 * crypto), so it runs identically under Node tests and the Cloudflare
 * Worker, and the security-critical path is fully unit-tested.
 *
 * Guarantees enforced here (see docs/ANCHORING_PROTOCOL.md):
 *   - only enrolled clients, only valid client signatures are anchored
 *   - seq must be exactly last+1 and prev_anchor_head must match the stored
 *     head — anything else is a CONFLICT, quarantined, NEVER overwritten
 *     (this is the anti-replay, anti-drop, and stolen-key-fork defense)
 *   - every accepted anchor is countersigned with a trusted server
 *     timestamp; the client keeps that receipt as proof
 */

const STATUS = {
  ENROLLED: "ENROLLED",
  ANCHORED: "ANCHORED",
  REJECTED: "REJECTED",
  CONFLICT: "CONFLICT",
};

async function enroll({ clientId, publicKeyPem }, deps) {
  if (!clientId || !publicKeyPem) {
    return { status: STATUS.REJECTED, reason: "clientId and publicKeyPem required" };
  }
  const existing = await deps.store.getClientPublicKey(clientId);
  if (existing && existing !== publicKeyPem) {
    // Never silently rebind a client to a new key — that would let an
    // attacker hijack an existing log_id's anchor stream.
    return { status: STATUS.REJECTED, reason: "clientId already enrolled with a different key" };
  }
  await deps.store.enrollClient(clientId, publicKeyPem);
  return { status: STATUS.ENROLLED, clientId };
}

async function processSubmission(batch, deps) {
  const { store, crypto, serverPrivateKeyPem, now } = deps;
  const ts = () => (now ? now() : new Date().toISOString());

  if (
    !batch ||
    batch.v !== 1 ||
    !batch.client_id ||
    !batch.log_id ||
    typeof batch.seq !== "number" ||
    !batch.chain_head ||
    !batch.sig
  ) {
    return { status: STATUS.REJECTED, reason: "malformed batch" };
  }

  const pub = await store.getClientPublicKey(batch.client_id);
  if (!pub) return { status: STATUS.REJECTED, reason: "unknown client" };

  if (!(await crypto.verifyClientSig(batch, pub))) {
    return { status: STATUS.REJECTED, reason: "bad signature" };
  }

  const last = await store.getLastAnchor(batch.log_id);
  const expectedSeq = (last ? last.seq : 0) + 1;
  const expectedPrev = last ? last.chain_head : "GENESIS";

  if (batch.seq !== expectedSeq || batch.prev_anchor_head !== expectedPrev) {
    const reason = batch.seq !== expectedSeq ? "seq_mismatch" : "prev_head_mismatch";
    await store.quarantine(batch.log_id, {
      batch,
      expectedSeq,
      expectedPrev,
      reason,
      at: ts(),
    });
    return { status: STATUS.CONFLICT, reason, expectedSeq, expectedPrev };
  }

  const tsServer = ts();
  const serverSig = await crypto.countersign(batch, tsServer, serverPrivateKeyPem);
  const record = {
    seq: batch.seq,
    log_id: batch.log_id,
    client_id: batch.client_id,
    entry_count: batch.entry_count,
    chain_head: batch.chain_head,
    prev_anchor_head: batch.prev_anchor_head,
    ts_client: batch.ts_client,
    ts_server: tsServer,
    server_sig: serverSig,
    sig: batch.sig,
  };
  await store.putAnchor(batch.log_id, record);
  return {
    status: STATUS.ANCHORED,
    receipt: { seq: batch.seq, log_id: batch.log_id, ts_server: tsServer, server_sig: serverSig },
  };
}

module.exports = { STATUS, enroll, processSubmission };
