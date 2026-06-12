/**
 * CORD Anchoring — zero-knowledge chain-head countersigning (client side).
 *
 * The audit log (logger.js) is a SHA-256 hash chain. verifyChain() proves
 * INTERNAL consistency, but an attacker who owns the box can regenerate a
 * clean fake chain from genesis — a self-contained chain proves nothing to
 * a third party. Anchoring fixes the trust root: periodically the client
 * signs the current chain head + a monotonic sequence number and sends ONLY
 * that (~300 bytes, no log payloads) to an external anchor service, which
 * countersigns it with a trusted timestamp. History older than the last
 * anchor can no longer be rewritten without the recomputed head diverging
 * from what was anchored.
 *
 * This module is the locally-verifiable client core: Ed25519 keys, signed
 * anchor batches, chain-head-at-N extraction, and the tamper-detecting
 * verify logic. The anchor service (Cloudflare Worker) is separate.
 *
 * See docs/ANCHORING_PROTOCOL.md.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { appendLog, verifyChain, readLastLine, LOG_PATH } = require("./logger");

const BATCH_VERSION = 1;
const ANCHOR_DIR_DEFAULT = path.join(os.homedir(), ".cord");

// ── Canonical serialization ──────────────────────────────────────────────────
// Deterministic, fixed key order, excludes `sig`. Both signing and
// verification serialize the same way so the signature is stable.
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

// ── Keys (Ed25519) ───────────────────────────────────────────────────────────
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

/**
 * Load the client keypair, generating it on first use. Private key is
 * written 0600 and never leaves the machine.
 */
function loadOrCreateKey(dir = ANCHOR_DIR_DEFAULT) {
  fs.mkdirSync(dir, { recursive: true });
  const keyPath = path.join(dir, "anchor.key");
  const pubPath = path.join(dir, "anchor.pub");
  if (fs.existsSync(keyPath)) {
    return {
      privateKeyPem: fs.readFileSync(keyPath, "utf8"),
      publicKeyPem: fs.readFileSync(pubPath, "utf8"),
      created: false,
    };
  }
  const kp = generateKeypair();
  fs.writeFileSync(keyPath, kp.privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(pubPath, kp.publicKeyPem, { mode: 0o644 });
  return { ...kp, created: true };
}

// ── log_id: stable identity for a given chain ────────────────────────────────
function computeLogId(clientId, logPath, genesisTime) {
  return crypto
    .createHash("sha256")
    .update(`${clientId}\n${path.resolve(logPath)}\n${genesisTime}`)
    .digest("hex");
}

// ── Reading the local chain ──────────────────────────────────────────────────
function countEntries(logPath) {
  if (!fs.existsSync(logPath)) return 0;
  return fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).length;
}

/** Current head hash + entry count of a log file. */
function chainHeadOf(logPath = LOG_PATH) {
  if (!fs.existsSync(logPath)) return { chainHead: "GENESIS", entryCount: 0 };
  const last = readLastLine(logPath);
  if (!last) return { chainHead: "GENESIS", entryCount: 0 };
  let chainHead = "GENESIS";
  try {
    chainHead = JSON.parse(last).entry_hash || "GENESIS";
  } catch {
    /* unparsable tail — treated as no head */
  }
  return { chainHead, entryCount: countEntries(logPath) };
}

/**
 * entry_hash of the Nth entry (1-indexed). Returns null if the log has
 * fewer than N entries (truncation) or the line is unparsable. This is how
 * an anchor's claim ("at N entries the head was H") is re-checked.
 * NOTE: v1 reads plaintext logs; encrypted-log verification is deferred.
 */
function headAtEntry(logPath, n) {
  if (n <= 0) return "GENESIS";
  if (!fs.existsSync(logPath)) return null;
  const lines = fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean);
  if (lines.length < n) return null;
  try {
    return JSON.parse(lines[n - 1]).entry_hash || null;
  } catch {
    return null;
  }
}

// ── Anchor batches ───────────────────────────────────────────────────────────
function buildBatch({
  clientId,
  logId,
  seq,
  entryCount,
  chainHead,
  prevAnchorHead,
  tsClient,
}) {
  return {
    v: BATCH_VERSION,
    client_id: clientId,
    log_id: logId,
    seq,
    entry_count: entryCount,
    chain_head: chainHead,
    prev_anchor_head: prevAnchorHead || "GENESIS",
    ts_client: tsClient,
  };
}

function signBatch(batch, privateKeyPem) {
  const sig = crypto.sign(null, Buffer.from(canonicalBatch(batch)), privateKeyPem);
  return { ...batch, sig: sig.toString("base64") };
}

function verifyBatchSig(batch, publicKeyPem) {
  if (!batch || !batch.sig) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalBatch(batch)),
      publicKeyPem,
      Buffer.from(batch.sig, "base64"),
    );
  } catch {
    return false;
  }
}

// ── Local anchor state (seq + prev_anchor_head, persisted) ───────────────────
function statePath(dir) {
  return path.join(dir, "anchor.state.json");
}
function loadState(dir = ANCHOR_DIR_DEFAULT) {
  const p = statePath(dir);
  if (!fs.existsSync(p)) return { seq: 0, prev_anchor_head: "GENESIS", log_id: null };
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return { seq: 0, prev_anchor_head: "GENESIS", log_id: null };
  }
}
function saveState(dir, state) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(statePath(dir), JSON.stringify(state, null, 2) + "\n");
}

/**
 * Build the next signed anchor batch for a log: reads the current head,
 * increments seq, chains prev_anchor_head, signs, and persists state.
 * Returns the signed batch (what the client would POST to the service).
 */
function createAnchor({
  logPath = LOG_PATH,
  clientId,
  dir = ANCHOR_DIR_DEFAULT,
  tsClient,
  genesisTime = "genesis",
}) {
  if (!clientId) throw new Error("createAnchor: clientId is required");
  const { privateKeyPem } = loadOrCreateKey(dir);
  const state = loadState(dir);
  const logId = state.log_id || computeLogId(clientId, logPath, genesisTime);
  const { chainHead, entryCount } = chainHeadOf(logPath);
  const seq = (state.seq || 0) + 1;
  const batch = buildBatch({
    clientId,
    logId,
    seq,
    entryCount,
    chainHead,
    prevAnchorHead: state.prev_anchor_head || "GENESIS",
    tsClient: tsClient || new Date().toISOString(),
  });
  const signed = signBatch(batch, privateKeyPem);
  saveState(dir, { seq, prev_anchor_head: chainHead, log_id: logId });
  return signed;
}

// ── Verification against anchors ─────────────────────────────────────────────
const STATUS = {
  VERIFIED: "VERIFIED",
  TAMPERED: "TAMPERED",
  NO_ANCHORS: "NO ANCHORS",
};

/**
 * Verify a local log against a set of anchors (each: {seq, entry_count,
 * chain_head, prev_anchor_head}). Returns { status, entries, anchorCount,
 * unanchoredTail, issues[] }.
 *
 *  - Chain internally broken            → TAMPERED (chain_broken)
 *  - No anchors                         → NO ANCHORS
 *  - Recomputed head ≠ anchored head    → TAMPERED (head_mismatch, names seq/entry_count)
 *  - Log shorter than anchored count    → TAMPERED (truncated)
 *  - prev_anchor_head doesn't chain     → TAMPERED (anchor_chain_break)
 *  - else                               → VERIFIED (+ unanchoredTail if recent
 *                                         entries aren't anchored yet)
 */
function verifyAgainstAnchors(logPath, anchors) {
  const chain = verifyChain(logPath);
  const out = {
    status: null,
    entries: chain.entries,
    anchorCount: anchors ? anchors.length : 0,
    unanchoredTail: 0,
    issues: [],
  };

  if (!chain.valid) {
    out.status = STATUS.TAMPERED;
    out.issues.push({ type: "chain_broken", errors: chain.errors });
    return out;
  }

  if (!anchors || anchors.length === 0) {
    out.status = STATUS.NO_ANCHORS;
    return out;
  }

  const sorted = [...anchors].sort((a, b) => a.seq - b.seq);
  let prevHead = "GENESIS";
  for (const a of sorted) {
    if (a.prev_anchor_head !== undefined && a.prev_anchor_head !== prevHead) {
      out.issues.push({
        type: "anchor_chain_break",
        seq: a.seq,
        expected: prevHead,
        got: a.prev_anchor_head,
      });
    }
    const recomputed = headAtEntry(logPath, a.entry_count);
    if (recomputed === null) {
      out.issues.push({
        type: "truncated",
        seq: a.seq,
        anchored_entry_count: a.entry_count,
        local_entries: chain.entries,
      });
    } else if (recomputed !== a.chain_head) {
      out.issues.push({
        type: "head_mismatch",
        seq: a.seq,
        entry_count: a.entry_count,
        anchored: a.chain_head,
        recomputed,
      });
    }
    prevHead = a.chain_head;
  }

  const lastAnchored = sorted[sorted.length - 1].entry_count;
  out.unanchoredTail = Math.max(0, chain.entries - lastAnchored);
  out.status = out.issues.length ? STATUS.TAMPERED : STATUS.VERIFIED;
  return out;
}

module.exports = {
  BATCH_VERSION,
  ANCHOR_DIR_DEFAULT,
  STATUS,
  canonicalBatch,
  generateKeypair,
  loadOrCreateKey,
  computeLogId,
  chainHeadOf,
  headAtEntry,
  countEntries,
  buildBatch,
  signBatch,
  verifyBatchSig,
  loadState,
  saveState,
  createAnchor,
  verifyAgainstAnchors,
};
