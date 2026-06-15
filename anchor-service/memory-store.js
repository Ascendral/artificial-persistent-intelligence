/**
 * In-memory store for tests and local dev. Production uses a strongly
 * consistent backend (D1) — see worker.js. The interface is the contract
 * logic.js depends on; any backend that implements it works.
 *
 * Strong consistency on getLastAnchor/putAnchor matters: seq monotonicity
 * is the anti-replay / anti-drop defense, so the prod backend must NOT be
 * eventually consistent for these two calls.
 */

function createMemoryStore() {
  const clients = new Map(); // clientId -> publicKeyPem
  const anchors = new Map(); // logId   -> [record, ...] (append-only)
  const quarantine = new Map(); // logId -> [conflict, ...]

  return {
    async enrollClient(clientId, publicKeyPem) {
      clients.set(clientId, publicKeyPem);
    },
    async getClientPublicKey(clientId) {
      return clients.get(clientId) || null;
    },
    async getLastAnchor(logId) {
      const a = anchors.get(logId);
      return a && a.length ? a[a.length - 1] : null;
    },
    async putAnchor(logId, record) {
      if (!anchors.has(logId)) anchors.set(logId, []);
      anchors.get(logId).push(record);
    },
    async listAnchors(logId) {
      return anchors.get(logId) || [];
    },
    async quarantine(logId, conflict) {
      if (!quarantine.has(logId)) quarantine.set(logId, []);
      quarantine.get(logId).push(conflict);
    },
    async listQuarantine(logId) {
      return quarantine.get(logId) || [];
    },
  };
}

module.exports = { createMemoryStore };
