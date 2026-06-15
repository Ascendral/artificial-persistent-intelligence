/**
 * Web Crypto adapter — the crypto path the Cloudflare Worker actually runs
 * (Workers have no node:crypto). Identical interface to crypto-node.js.
 *
 * Ed25519 is RFC 8032, so signatures produced by the client's node:crypto
 * are verifiable here and vice versa — proven by the interop test in
 * logic.test.js (Node v18.4+ exposes Ed25519 via WebCrypto, same as Workers).
 */

const { canonicalBatch, countersignData } = require("../cord/anchor-canonical");

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}

const ENC = new TextEncoder();

/** Build an adapter bound to a given SubtleCrypto (Workers: crypto.subtle). */
function makeWebCrypto(subtle) {
  return {
    async verifyClientSig(batch, clientPublicKeyPem) {
      if (!batch || !batch.sig) return false;
      try {
        const key = await subtle.importKey(
          "spki",
          pemToDer(clientPublicKeyPem),
          { name: "Ed25519" },
          false,
          ["verify"],
        );
        return await subtle.verify(
          { name: "Ed25519" },
          key,
          b64ToBytes(batch.sig),
          ENC.encode(canonicalBatch(batch)),
        );
      } catch {
        return false;
      }
    },

    async countersign(batch, tsServer, serverPrivateKeyPem) {
      const key = await subtle.importKey(
        "pkcs8",
        pemToDer(serverPrivateKeyPem),
        { name: "Ed25519" },
        false,
        ["sign"],
      );
      const sig = await subtle.sign(
        { name: "Ed25519" },
        key,
        ENC.encode(countersignData(batch, tsServer)),
      );
      return bytesToB64(sig);
    },
  };
}

module.exports = { makeWebCrypto, pemToDer };
