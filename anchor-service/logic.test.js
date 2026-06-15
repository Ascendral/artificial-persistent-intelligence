/**
 * Anchor service protocol tests — real Ed25519, real chains, in-memory store.
 *
 * Covers the security-critical path: enrollment, signature checks, seq /
 * prev_head continuity (anti-replay / anti-drop), countersigned receipts,
 * crypto interop with the Worker's Web Crypto path, and the full
 * client → server → verify loop including a tamper that gets caught.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { webcrypto } = require("crypto");

const { appendLog } = require("../cord/logger");
const clientAnchor = require("../cord/anchor");
const { STATUS, enroll, processSubmission } = require("./logic");
const { createMemoryStore } = require("./memory-store");
const nodeCrypto = require("./crypto-node");
const { makeWebCrypto } = require("./crypto-web");

let tmp;
const CLIENT_ID = "c_test";
let serverKey;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cord-svc-"));
  serverKey = nodeCrypto.generateServerKey();
});
afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

function deps(store, crypto = nodeCrypto) {
  return { store, crypto, serverPrivateKeyPem: serverKey.privateKeyPem, now: () => "2026-06-12T00:00:00.000Z" };
}

async function enrolledStore() {
  const store = createMemoryStore();
  const { publicKeyPem } = clientAnchor.loadOrCreateKey(tmp);
  await enroll({ clientId: CLIENT_ID, publicKeyPem }, { store });
  return store;
}

/** Build a real n-entry log and a signed anchor over it. */
function logAndAnchor(n, tsClient = "t1") {
  const logPath = path.join(tmp, "audit.jsonl");
  for (let i = 0; i < n; i++) appendLog({ decision: "ALLOW", score: 1, i }, logPath);
  const batch = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient });
  return { logPath, batch };
}

describe("anchor service — enrollment + signature checks", () => {
  test("valid submission is ANCHORED and the receipt verifies against the server key", async () => {
    const store = await enrolledStore();
    const { batch } = logAndAnchor(3);
    const r = await processSubmission(batch, deps(store));
    expect(r.status).toBe(STATUS.ANCHORED);
    // Client verifies the server actually countersigned THIS batch.
    const ok = clientAnchor.verifyReceipt(batch, r.receipt.ts_server, r.receipt.server_sig, serverKey.publicKeyPem);
    expect(ok).toBe(true);
  });

  test("unknown client is REJECTED", async () => {
    const store = createMemoryStore(); // nobody enrolled
    const { batch } = logAndAnchor(2);
    const r = await processSubmission(batch, deps(store));
    expect(r.status).toBe(STATUS.REJECTED);
    expect(r.reason).toMatch(/unknown client/);
  });

  test("tampered batch (bad signature) is REJECTED", async () => {
    const store = await enrolledStore();
    const { batch } = logAndAnchor(3);
    const forged = { ...batch, chain_head: "deadbeef" }; // sig no longer matches
    const r = await processSubmission(forged, deps(store));
    expect(r.status).toBe(STATUS.REJECTED);
    expect(r.reason).toMatch(/bad signature/);
  });

  test("enrolling a client_id with a different key is refused", async () => {
    const store = await enrolledStore();
    const other = nodeCrypto.generateServerKey(); // any other Ed25519 pub
    const r = await enroll({ clientId: CLIENT_ID, publicKeyPem: other.publicKeyPem }, { store });
    expect(r.status).toBe(STATUS.REJECTED);
    expect(r.reason).toMatch(/different key/);
  });
});

describe("anchor service — seq + prev_head continuity (anti-replay / anti-drop)", () => {
  test("a seq gap is a CONFLICT and is quarantined, never stored as an anchor", async () => {
    const store = await enrolledStore();
    const logPath = path.join(tmp, "audit.jsonl");
    for (let i = 0; i < 3; i++) appendLog({ decision: "ALLOW", score: 1, i }, logPath);
    // Force seq=1 to be skipped by bumping local state to 1 first via a throwaway anchor we DON'T submit.
    clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t0" }); // seq1, not submitted
    appendLog({ decision: "ALLOW", score: 1, i: 9 }, logPath);
    const batch2 = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t2" }); // seq2
    const r = await processSubmission(batch2, deps(store)); // server expects seq1
    expect(r.status).toBe(STATUS.CONFLICT);
    expect(r.reason).toBe("seq_mismatch");
    expect((await store.listAnchors(batch2.log_id)).length).toBe(0);
    expect((await store.listQuarantine(batch2.log_id)).length).toBe(1);
  });

  test("replaying the same anchor is a CONFLICT (seq already consumed)", async () => {
    const store = await enrolledStore();
    const { batch } = logAndAnchor(2);
    expect((await processSubmission(batch, deps(store))).status).toBe(STATUS.ANCHORED);
    const replay = await processSubmission(batch, deps(store)); // same seq=1 again
    expect(replay.status).toBe(STATUS.CONFLICT);
    expect(replay.reason).toBe("seq_mismatch");
  });

  test("a forged prev_anchor_head is a CONFLICT", async () => {
    const store = await enrolledStore();
    const logPath = path.join(tmp, "audit.jsonl");
    for (let i = 0; i < 2; i++) appendLog({ decision: "ALLOW", score: 1, i }, logPath);
    const a1 = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t1" });
    expect((await processSubmission(a1, deps(store))).status).toBe(STATUS.ANCHORED);
    appendLog({ decision: "ALLOW", score: 1, i: 3 }, logPath);
    // Build seq2 but lie about prev_anchor_head, then re-sign so the sig is valid.
    const a2 = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t2" });
    const lying = clientAnchor.signBatch(
      { ...a2, prev_anchor_head: "WRONG", sig: undefined },
      clientAnchor.loadOrCreateKey(tmp).privateKeyPem,
    );
    const r = await processSubmission(lying, deps(store));
    expect(r.status).toBe(STATUS.CONFLICT);
    expect(r.reason).toBe("prev_head_mismatch");
  });
});

describe("anchor service — Web Crypto interop (the Worker's actual crypto path)", () => {
  test("a node:crypto-signed batch verifies under Web Crypto, and its receipt verifies under node", async () => {
    const store = await enrolledStore();
    const { batch } = logAndAnchor(3);
    const web = makeWebCrypto(webcrypto.subtle);
    const r = await processSubmission(batch, deps(store, web)); // server uses Web Crypto
    expect(r.status).toBe(STATUS.ANCHORED);
    // Receipt countersigned via Web Crypto verifies with node:crypto client-side.
    const ok = clientAnchor.verifyReceipt(batch, r.receipt.ts_server, r.receipt.server_sig, serverKey.publicKeyPem);
    expect(ok).toBe(true);
  });
});

describe("anchor service — full client → server → verify loop", () => {
  test("two anchors accepted in order; verify against them is VERIFIED, then a tamper is caught", async () => {
    const store = await enrolledStore();
    const logPath = path.join(tmp, "audit.jsonl");
    for (let i = 0; i < 3; i++) appendLog({ decision: "ALLOW", score: 1, i }, logPath);
    const a1 = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t1" });
    expect((await processSubmission(a1, deps(store))).status).toBe(STATUS.ANCHORED);
    appendLog({ decision: "ALLOW", score: 1, i: 3 }, logPath);
    appendLog({ decision: "ALLOW", score: 1, i: 4 }, logPath);
    const a2 = clientAnchor.createAnchor({ logPath, clientId: CLIENT_ID, dir: tmp, tsClient: "t2" });
    expect((await processSubmission(a2, deps(store))).status).toBe(STATUS.ANCHORED);

    // Client pulls the service's anchor list and verifies the local log against it.
    const anchors = await store.listAnchors(a1.log_id);
    expect(anchors.length).toBe(2);
    const clean = clientAnchor.verifyAgainstAnchors(logPath, anchors);
    expect(clean.status).toBe(clientAnchor.STATUS.VERIFIED);

    // Now regenerate entries 4-5 validly (internally consistent) — the
    // anchored head at entry 5 no longer matches → TAMPERED.
    const lines = fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean);
    const forged = path.join(tmp, "forged.jsonl");
    fs.writeFileSync(forged, lines.slice(0, 3).join("\n") + "\n");
    appendLog({ decision: "ALLOW", score: 1, i: "EVIL" }, forged);
    appendLog({ decision: "ALLOW", score: 1, i: "EVIL2" }, forged);
    const tampered = clientAnchor.verifyAgainstAnchors(forged, anchors);
    expect(tampered.status).toBe(clientAnchor.STATUS.TAMPERED);
    expect(tampered.issues.some((x) => x.type === "head_mismatch" && x.seq === 2)).toBe(true);
  });
});
