#!/usr/bin/env node
/**
 * Generate the anchor service's Ed25519 keypair. Run once; load the private
 * key as a Worker secret and publish the public key via GET /pubkey.
 *
 *   node anchor-service/gen-server-key.js
 *   # then:
 *   wrangler secret put SERVER_PRIVATE_KEY_PEM   < paste private
 *   wrangler secret put SERVER_PUBLIC_KEY_PEM    < paste public
 */
const { generateServerKey } = require("./crypto-node");
const { publicKeyPem, privateKeyPem } = generateServerKey();
console.log("=== SERVER_PUBLIC_KEY_PEM (publish) ===\n" + publicKeyPem);
console.log("=== SERVER_PRIVATE_KEY_PEM (secret — never commit) ===\n" + privateKeyPem);
