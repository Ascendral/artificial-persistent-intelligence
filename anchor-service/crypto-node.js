/**
 * Node crypto adapter for the anchor service — used by the test suite and
 * any Node-hosted deployment. The Cloudflare Worker uses crypto-web.js
 * instead; both implement the same { verifyClientSig, countersign }
 * interface so logic.js is backend-agnostic.
 */

const crypto = require("crypto");
const { canonicalBatch, countersignData } = require("../cord/anchor-canonical");

function generateServerKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function verifyClientSig(batch, clientPublicKeyPem) {
  if (!batch || !batch.sig) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalBatch(batch)),
      clientPublicKeyPem,
      Buffer.from(batch.sig, "base64"),
    );
  } catch {
    return false;
  }
}

function countersign(batch, tsServer, serverPrivateKeyPem) {
  return crypto
    .sign(null, Buffer.from(countersignData(batch, tsServer)), serverPrivateKeyPem)
    .toString("base64");
}

module.exports = { generateServerKey, verifyClientSig, countersign };
