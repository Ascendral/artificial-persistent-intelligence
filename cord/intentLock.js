const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// The intent lock is a single on-disk file shared by every importer of this
// module. Under Jest, each test file runs in its own worker process but they all
// resolve to the same path — so concurrent workers overwrite/delete each other's
// lock, causing flaky evaluations (e.g. a benign proposal scored as if intent
// were unlocked). Give every Jest worker its own lock file so the state is
// isolated per process. This removes the cross-worker shared state rather than
// serializing the tests.
const LOCK_PATH = process.env.JEST_WORKER_ID
  ? path.join(__dirname, `intent.lock.worker-${process.env.JEST_WORKER_ID}.json`)
  : path.join(__dirname, "intent.lock.json");

function sha(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function setIntentLock({ user_id, passphrase, intent_text, scope }) {
  if (!user_id || !passphrase || !intent_text || !scope) {
    throw new Error("Missing required fields for intent lock");
  }
  // Serialize scope for JSON — convert RegExp to {__regex, flags} objects
  const serializableScope = { ...scope };
  if (Array.isArray(scope.allowCommands)) {
    serializableScope.allowCommands = scope.allowCommands.map((pattern) => {
      if (pattern instanceof RegExp) {
        return { __regex: pattern.source, flags: pattern.flags };
      }
      return pattern;
    });
  }
  const payload = {
    user_id,
    intent_text,
    scope: serializableScope,
    passphrase_hash: sha(passphrase),
    created_at: new Date().toISOString(),
  };
  fs.writeFileSync(LOCK_PATH, JSON.stringify(payload, null, 2), "utf8");
  return payload;
}

function loadIntentLock() {
  if (!fs.existsSync(LOCK_PATH)) return null;
  try {
    const data = fs.readFileSync(LOCK_PATH, "utf8");
    return JSON.parse(data);
  } catch {
    return null;
  }
}

function verifyPassphrase(passphrase_attempt) {
  const lock = loadIntentLock();
  if (!lock) return false;
  return sha(passphrase_attempt) === lock.passphrase_hash;
}

module.exports = {
  setIntentLock,
  loadIntentLock,
  verifyPassphrase,
  LOCK_PATH,
};
