/**
 * CORD Audit Logger — Hash-chained, redacted, optionally encrypted.
 *
 * Features:
 *   - SHA-256 hash-chained append-only log (tamper detection)
 *   - PII redaction: SSN, credit card, email, phone auto-scrubbed
 *   - Three redaction levels: "none" | "pii" | "full"
 *   - Optional AES-256-GCM encryption-at-rest
 *
 * Config via environment:
 *   CORD_LOG_REDACTION = "none" | "pii" | "full"  (default: "pii")
 *   CORD_LOG_KEY       = 64-char hex string        (enables encryption)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { PII_PATTERNS } = require("./policies");

const LOG_PATH = path.join(__dirname, "cord.log.jsonl");

// ── Configuration ────────────────────────────────────────────────────────────

let redactionLevel = process.env.CORD_LOG_REDACTION || "pii";
let encryptionKey = process.env.CORD_LOG_KEY || null;

function setRedactionLevel(level) {
  if (!["none", "pii", "full"].includes(level)) {
    throw new Error(
      `Invalid redaction level: ${level}. Use "none", "pii", or "full".`,
    );
  }
  redactionLevel = level;
}

function setEncryptionKey(key) {
  if (key && key.length !== 64) {
    throw new Error(
      "Encryption key must be a 64-character hex string (32 bytes).",
    );
  }
  encryptionKey = key || null;
}

function getRedactionLevel() {
  return redactionLevel;
}

// ── PII Redaction ────────────────────────────────────────────────────────────

function redactPII(text) {
  if (!text || typeof text !== "string") return text;

  if (redactionLevel === "none") return text;

  if (redactionLevel === "full") {
    const hash = crypto
      .createHash("sha256")
      .update(text)
      .digest("hex")
      .slice(0, 16);
    return `${hash}...[redacted]`;
  }

  // "pii" mode — replace known PII patterns
  let redacted = text;
  redacted = redacted.replace(PII_PATTERNS.ssn, "[SSN-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.creditCard, "[CC-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.email, "[EMAIL-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.phone, "[PHONE-REDACTED]");
  return redacted;
}

// ── Encryption ───────────────────────────────────────────────────────────────

function encryptEntry(jsonStr, keyOverride) {
  const activeKey = keyOverride || encryptionKey;
  if (!activeKey) return jsonStr;

  const key = Buffer.from(activeKey, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(jsonStr, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");

  return JSON.stringify({
    encrypted: true,
    iv: iv.toString("hex"),
    tag,
    data: encrypted,
  });
}

function decryptEntry(entryStr, keyOverride) {
  const activeKey = keyOverride || encryptionKey;
  if (!activeKey) return entryStr;

  let parsed;
  try {
    parsed = JSON.parse(entryStr);
  } catch {
    return entryStr;
  }
  if (!parsed.encrypted) return entryStr;

  const key = Buffer.from(activeKey, "hex");
  const iv = Buffer.from(parsed.iv, "hex");
  const tag = Buffer.from(parsed.tag, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(parsed.data, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ── Hash Chain ───────────────────────────────────────────────────────────────

function hashPayload(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

/**
 * Read the last non-empty line of a file without loading the whole file.
 *
 * getPrevHash() only needs the final entry, but the audit log is
 * append-only and unbounded — slurping it on every append made each
 * write O(file size), so the log was O(n²) to build. We seek from the
 * end and read backwards a chunk at a time until we have the last line.
 *
 * Newline (0x0A) never appears inside a UTF-8 multibyte sequence, so a
 * byte-wise newline search is safe across chunk boundaries. Returns the
 * exact same string the previous full-file read produced.
 */
function readLastLine(filePath) {
  const CHUNK = 8192;
  const fd = fs.openSync(filePath, "r");
  try {
    let pos = fs.fstatSync(fd).size;
    if (pos === 0) return "";
    let buf = Buffer.alloc(0);
    while (pos > 0) {
      const readSize = Math.min(CHUNK, pos);
      pos -= readSize;
      const chunk = Buffer.alloc(readSize);
      fs.readSync(fd, chunk, 0, readSize, pos);
      buf = Buffer.concat([chunk, buf]);

      // Ignore trailing newline byte(s) at the very end of the file.
      let end = buf.length;
      while (end > 0 && buf[end - 1] === 0x0a) end--;
      // Find the newline that begins the last line.
      let start = end - 1;
      for (; start >= 0; start--) {
        if (buf[start] === 0x0a) break;
      }
      if (start >= 0) return buf.slice(start + 1, end).toString("utf8");
      if (pos === 0) return buf.slice(0, end).toString("utf8");
    }
    return "";
  } finally {
    fs.closeSync(fd);
  }
}

function getPrevHash(logPath = LOG_PATH) {
  if (!fs.existsSync(logPath)) return "GENESIS";
  const lastLine = readLastLine(logPath);
  if (!lastLine) return "GENESIS";

  try {
    const content = encryptionKey ? decryptEntry(lastLine) : lastLine;
    const parsed = JSON.parse(content);
    return parsed.entry_hash || "GENESIS";
  } catch {
    return "GENESIS";
  }
}

// ── Core Logger ──────────────────────────────────────────────────────────────

function appendLog(entry, logPath = LOG_PATH) {
  // Redact sensitive fields
  const sanitized = { ...entry };
  if (sanitized.proposal) sanitized.proposal = redactPII(sanitized.proposal);
  if (sanitized.path) sanitized.path = redactPII(sanitized.path);
  if (sanitized.networkTarget)
    sanitized.networkTarget = redactPII(sanitized.networkTarget);

  // Build hash-chained entry
  const timestamp = new Date().toISOString();
  const prev_hash = getPrevHash(logPath);
  const base = { timestamp, prev_hash, ...sanitized };
  const entry_hash = hashPayload(prev_hash + JSON.stringify(base));
  const logEntry = { ...base, entry_hash };

  // Optionally encrypt, then write
  const line = encryptionKey
    ? encryptEntry(JSON.stringify(logEntry))
    : JSON.stringify(logEntry);

  fs.appendFileSync(logPath, line + "\n", "utf8");
  return entry_hash;
}

// ── Verification ─────────────────────────────────────────────────────────────

function verifyChain(logPath = LOG_PATH) {
  if (!fs.existsSync(logPath)) return { valid: true, entries: 0 };

  const lines = fs
    .readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean);
  let prevHash = "GENESIS";
  const errors = [];

  for (let i = 0; i < lines.length; i++) {
    try {
      const content = encryptionKey ? decryptEntry(lines[i]) : lines[i];
      const entry = JSON.parse(content);

      if (entry.prev_hash !== prevHash) {
        errors.push({ line: i + 1, expected: prevHash, got: entry.prev_hash });
      }
      prevHash = entry.entry_hash;
    } catch (err) {
      errors.push({ line: i + 1, error: err.message });
    }
  }

  return { valid: errors.length === 0, entries: lines.length, errors };
}

module.exports = {
  appendLog,
  verifyChain,
  redactPII,
  encryptEntry,
  decryptEntry,
  setRedactionLevel,
  setEncryptionKey,
  getRedactionLevel,
  readLastLine,
  LOG_PATH,
};
