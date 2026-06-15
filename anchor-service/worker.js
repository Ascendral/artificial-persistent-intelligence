/**
 * CORD anchor service — Cloudflare Worker entry point.
 *
 * Thin adapter: HTTP routing + D1-backed store + Web Crypto, all delegating
 * to the dependency-injected logic.js (which is fully unit-tested in
 * logic.test.js, including this exact Web Crypto path). The Worker itself
 * runs only in the Workers runtime, so it is exercised via `wrangler dev` /
 * deploy, not the Node test suite — see README.md.
 *
 * Endpoints:
 *   POST /enroll        { clientId, publicKeyPem }            -> { status }
 *   POST /anchor        <signed batch>                         -> { status, receipt? }
 *   GET  /anchors/:logId                                       -> { anchors[] }
 *   GET  /pubkey                                               -> { server_public_key }
 *
 * Secrets (wrangler secret put):
 *   SERVER_PRIVATE_KEY_PEM   Ed25519 PKCS8 PEM — countersigning key
 *   SERVER_PUBLIC_KEY_PEM    Ed25519 SPKI PEM  — published for receipt verify
 */

import * as logic from "./logic.js";
import { makeWebCrypto } from "./crypto-web.js";

function d1Store(db) {
  return {
    async enrollClient(clientId, pem) {
      await db
        .prepare("INSERT INTO clients(client_id, public_key) VALUES(?, ?) ON CONFLICT(client_id) DO NOTHING")
        .bind(clientId, pem)
        .run();
    },
    async getClientPublicKey(clientId) {
      const r = await db.prepare("SELECT public_key FROM clients WHERE client_id = ?").bind(clientId).first();
      return r ? r.public_key : null;
    },
    async getLastAnchor(logId) {
      // Strongly consistent read — seq monotonicity is the anti-replay gate.
      return (
        (await db.prepare("SELECT * FROM anchors WHERE log_id = ? ORDER BY seq DESC LIMIT 1").bind(logId).first()) ||
        null
      );
    },
    async putAnchor(logId, r) {
      // PRIMARY KEY(log_id, seq) makes a duplicate seq a hard DB error —
      // defense in depth behind logic.js's seq check.
      await db
        .prepare(
          "INSERT INTO anchors(log_id, seq, client_id, entry_count, chain_head, prev_anchor_head, ts_client, ts_server, server_sig, sig) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(
          logId,
          r.seq,
          r.client_id,
          r.entry_count,
          r.chain_head,
          r.prev_anchor_head,
          r.ts_client,
          r.ts_server,
          r.server_sig,
          r.sig,
        )
        .run();
    },
    async listAnchors(logId) {
      const r = await db.prepare("SELECT * FROM anchors WHERE log_id = ? ORDER BY seq ASC").bind(logId).all();
      return r.results || [];
    },
    async quarantine(logId, conflict) {
      await db
        .prepare("INSERT INTO quarantine(log_id, payload, at) VALUES(?, ?, ?)")
        .bind(logId, JSON.stringify(conflict), conflict.at)
        .run();
    },
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const json = (o, status = 200) =>
      new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });

    try {
      const store = d1Store(env.DB);
      const crypto = makeWebCrypto(globalThis.crypto.subtle);

      if (req.method === "POST" && url.pathname === "/enroll") {
        const body = await req.json();
        const r = await logic.enroll(body, { store });
        return json(r, r.status === logic.STATUS.ENROLLED ? 200 : 400);
      }

      if (req.method === "POST" && url.pathname === "/anchor") {
        const batch = await req.json();
        const r = await logic.processSubmission(batch, {
          store,
          crypto,
          serverPrivateKeyPem: env.SERVER_PRIVATE_KEY_PEM,
        });
        const code = r.status === logic.STATUS.ANCHORED ? 200 : r.status === logic.STATUS.CONFLICT ? 409 : 400;
        return json(r, code);
      }

      if (req.method === "GET" && url.pathname.startsWith("/anchors/")) {
        const logId = decodeURIComponent(url.pathname.slice("/anchors/".length));
        return json({ log_id: logId, anchors: await store.listAnchors(logId) });
      }

      if (req.method === "GET" && url.pathname === "/pubkey") {
        return json({ server_public_key: env.SERVER_PUBLIC_KEY_PEM });
      }

      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};
