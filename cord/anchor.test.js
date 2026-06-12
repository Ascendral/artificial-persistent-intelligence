/**
 * Tests for anchor.js — Ed25519 anchor batches + tamper-detecting verify.
 *
 * Chains are built with the REAL logger (appendLog into a temp path), and
 * signatures use REAL Ed25519 via node:crypto. No mocks of the crypto or
 * chain primitives — if these pass, the mechanism actually works.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { appendLog } = require("./logger");
const {
  generateKeypair,
  loadOrCreateKey,
  computeLogId,
  chainHeadOf,
  headAtEntry,
  signBatch,
  verifyBatchSig,
  buildBatch,
  createAnchor,
  verifyAgainstAnchors,
  loadState,
  STATUS,
} = require("./anchor");

let tmpDir;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cord-anchor-"));
});
afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function logPath() {
  return path.join(tmpDir, "audit.jsonl");
}

/** Append n entries to a fresh log; return the path. */
function buildLog(n) {
  const p = logPath();
  for (let i = 0; i < n; i++) appendLog({ decision: "ALLOW", score: 1, i }, p);
  return p;
}

/** Construct an honest anchor for the log at `entryCount` entries. */
function anchorAt(p, seq, entryCount, prevAnchorHead) {
  return {
    seq,
    entry_count: entryCount,
    chain_head: headAtEntry(p, entryCount),
    prev_anchor_head: prevAnchorHead,
  };
}

describe("anchor — Ed25519 batch signing", () => {
  test("sign/verify roundtrip succeeds with a real keypair", () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    const batch = buildBatch({
      clientId: "c_test",
      logId: "log123",
      seq: 1,
      entryCount: 10,
      chainHead: "abc",
      prevAnchorHead: "GENESIS",
      tsClient: "2026-06-12T00:00:00.000Z",
    });
    const signed = signBatch(batch, privateKeyPem);
    expect(typeof signed.sig).toBe("string");
    expect(verifyBatchSig(signed, publicKeyPem)).toBe(true);
  });

  test("tampering any signed field breaks the signature", () => {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    const signed = signBatch(
      buildBatch({
        clientId: "c_test",
        logId: "log123",
        seq: 1,
        entryCount: 10,
        chainHead: "abc",
        prevAnchorHead: "GENESIS",
        tsClient: "2026-06-12T00:00:00.000Z",
      }),
      privateKeyPem,
    );
    expect(verifyBatchSig(signed, publicKeyPem)).toBe(true);

    const forgedHead = { ...signed, chain_head: "deadbeef" };
    expect(verifyBatchSig(forgedHead, publicKeyPem)).toBe(false);

    const forgedCount = { ...signed, entry_count: 9 };
    expect(verifyBatchSig(forgedCount, publicKeyPem)).toBe(false);

    const forgedSig = { ...signed, sig: Buffer.from("nope").toString("base64") };
    expect(verifyBatchSig(forgedSig, publicKeyPem)).toBe(false);
  });

  test("a different key cannot verify the signature", () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const signed = signBatch(
      buildBatch({
        clientId: "c",
        logId: "l",
        seq: 1,
        entryCount: 1,
        chainHead: "h",
        prevAnchorHead: "GENESIS",
        tsClient: "t",
      }),
      a.privateKeyPem,
    );
    expect(verifyBatchSig(signed, a.publicKeyPem)).toBe(true);
    expect(verifyBatchSig(signed, b.publicKeyPem)).toBe(false);
  });
});

describe("anchor — log_id and chain reads", () => {
  test("computeLogId is deterministic and input-sensitive", () => {
    const a = computeLogId("c1", "/x/log.jsonl", "g");
    const b = computeLogId("c1", "/x/log.jsonl", "g");
    const c = computeLogId("c2", "/x/log.jsonl", "g");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  test("headAtEntry returns the right hash and null past the end", () => {
    const p = buildLog(5);
    const { chainHead, entryCount } = chainHeadOf(p);
    expect(entryCount).toBe(5);
    expect(headAtEntry(p, 5)).toBe(chainHead);
    expect(headAtEntry(p, 3)).not.toBe(chainHead);
    expect(headAtEntry(p, 3)).toBeTruthy();
    expect(headAtEntry(p, 6)).toBeNull(); // beyond the log
  });
});

describe("anchor — createAnchor", () => {
  test("produces a valid signed batch, increments seq, chains prev_anchor_head", () => {
    const p = buildLog(3);
    const { publicKeyPem } = loadOrCreateKey(tmpDir);

    const a1 = createAnchor({ logPath: p, clientId: "c_test", dir: tmpDir, tsClient: "t1" });
    expect(a1.seq).toBe(1);
    expect(a1.prev_anchor_head).toBe("GENESIS");
    expect(a1.entry_count).toBe(3);
    expect(verifyBatchSig(a1, publicKeyPem)).toBe(true);

    appendLog({ decision: "ALLOW", score: 1, i: 99 }, p); // grow to 4
    const a2 = createAnchor({ logPath: p, clientId: "c_test", dir: tmpDir, tsClient: "t2" });
    expect(a2.seq).toBe(2);
    expect(a2.prev_anchor_head).toBe(a1.chain_head); // anchors chain
    expect(a2.entry_count).toBe(4);
    expect(loadState(tmpDir).seq).toBe(2);
  });
});

describe("anchor — verifyAgainstAnchors", () => {
  test("clean log matching its anchors → VERIFIED", () => {
    const p = buildLog(5);
    const a1 = anchorAt(p, 1, 3, "GENESIS");
    const a2 = anchorAt(p, 2, 5, a1.chain_head);
    const r = verifyAgainstAnchors(p, [a1, a2]);
    expect(r.status).toBe(STATUS.VERIFIED);
    expect(r.issues).toHaveLength(0);
    expect(r.unanchoredTail).toBe(0);
  });

  test("no anchors → NO ANCHORS (self-attested only)", () => {
    const p = buildLog(3);
    const r = verifyAgainstAnchors(p, []);
    expect(r.status).toBe(STATUS.NO_ANCHORS);
  });

  test("recent entries beyond the last anchor are reported as unanchored tail, still VERIFIED", () => {
    const p = buildLog(5);
    const a1 = anchorAt(p, 1, 3, "GENESIS");
    appendLog({ decision: "ALLOW", score: 1, i: 100 }, p); // 6 entries, anchor only covers 3
    const r = verifyAgainstAnchors(p, [a1]);
    expect(r.status).toBe(STATUS.VERIFIED);
    expect(r.unanchoredTail).toBe(3); // entries 4,5,6 not yet anchored
  });

  test("KILLER: a regenerated INTERNALLY-VALID chain is caught by the anchor", () => {
    // Honest log of 5, anchored at 3 and 5.
    const p = buildLog(5);
    const a1 = anchorAt(p, 1, 3, "GENESIS");
    const a2 = anchorAt(p, 2, 5, a1.chain_head);

    // Attacker keeps entries 1-3, then rewrites 4-5 with DIFFERENT content,
    // re-hashing validly so the chain passes verifyChain() (internal
    // consistency). This is the attack a self-contained chain can't catch.
    const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
    const forged = path.join(tmpDir, "forged.jsonl");
    fs.writeFileSync(forged, lines.slice(0, 3).join("\n") + "\n");
    appendLog({ decision: "ALLOW", score: 1, i: "EVIL-4" }, forged);
    appendLog({ decision: "ALLOW", score: 1, i: "EVIL-5" }, forged);

    // Sanity: the forged chain IS internally valid (would fool verifyChain).
    const { verifyChain } = require("./logger");
    expect(verifyChain(forged).valid).toBe(true);

    // But the anchor catches it: entry 3 still matches, entry 5 diverges.
    const r = verifyAgainstAnchors(forged, [a1, a2]);
    expect(r.status).toBe(STATUS.TAMPERED);
    const mismatch = r.issues.find((x) => x.type === "head_mismatch");
    expect(mismatch).toBeTruthy();
    expect(mismatch.seq).toBe(2); // names the window: between anchor 1 and 2
    expect(mismatch.entry_count).toBe(5);
    // anchor 1 (entry 3) is unaffected — no issue references seq 1
    expect(r.issues.some((x) => x.seq === 1)).toBe(false);
  });

  test("truncating the log below an anchored entry count → TAMPERED (truncated)", () => {
    const p = buildLog(5);
    const a2 = anchorAt(p, 1, 5, "GENESIS");
    // Chop to 4 entries.
    const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
    fs.writeFileSync(p, lines.slice(0, 4).join("\n") + "\n");
    const r = verifyAgainstAnchors(p, [a2]);
    expect(r.status).toBe(STATUS.TAMPERED);
    expect(r.issues.some((x) => x.type === "truncated")).toBe(true);
  });

  test("an internally broken chain → TAMPERED (chain_broken)", () => {
    const p = buildLog(3);
    const lines = fs.readFileSync(p, "utf8").split("\n").filter(Boolean);
    const e = JSON.parse(lines[1]);
    e.prev_hash = "tampered"; // break the link without re-hashing
    lines[1] = JSON.stringify(e);
    fs.writeFileSync(p, lines.join("\n") + "\n");
    const a = anchorAt(p, 1, 3, "GENESIS");
    const r = verifyAgainstAnchors(p, [a]);
    expect(r.status).toBe(STATUS.TAMPERED);
    expect(r.issues.some((x) => x.type === "chain_broken")).toBe(true);
  });
});
