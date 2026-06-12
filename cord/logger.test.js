/**
 * Tests for logger.js PII redaction and encryption (v4.1)
 */

const fs = require("fs");
const path = require("path");
const {
  redactPII,
  encryptEntry,
  decryptEntry,
  setRedactionLevel,
  setEncryptionKey,
  getRedactionLevel,
  appendLog,
  verifyChain,
  readLastLine,
  LOG_PATH,
} = require("./logger");

// Use a temporary log path for tests
const TEST_LOG = path.join(__dirname, "..", "cord.log.test.jsonl");

beforeEach(() => {
  // Reset to defaults
  setRedactionLevel("pii");
  setEncryptionKey(null);
  // Clean test log
  try {
    fs.unlinkSync(TEST_LOG);
  } catch {}
});

afterAll(() => {
  try {
    fs.unlinkSync(TEST_LOG);
  } catch {}
  setRedactionLevel("pii");
  setEncryptionKey(null);
});

describe("readLastLine() — O(1) tail read", () => {
  const os = require("os");
  let f;

  afterEach(() => {
    try {
      fs.unlinkSync(f);
    } catch {}
  });

  function write(content) {
    f = path.join(os.tmpdir(), `cord-lastline-${Date.now()}-${Math.random()}`);
    fs.writeFileSync(f, content);
    return f;
  }

  test("returns the last line of a multi-line file with trailing newline", () => {
    expect(readLastLine(write("a\nb\nc\n"))).toBe("c");
  });

  test("returns the last line without a trailing newline", () => {
    expect(readLastLine(write("a\nb\nlast"))).toBe("last");
  });

  test("returns the only line of a single-line file", () => {
    expect(readLastLine(write("solo\n"))).toBe("solo");
  });

  test("returns empty string for an empty file", () => {
    expect(readLastLine(write(""))).toBe("");
  });

  test("ignores multiple trailing newlines", () => {
    expect(readLastLine(write("x\ny\n\n\n"))).toBe("y");
  });

  test("reads a last line longer than the 8192-byte chunk", () => {
    const big = "z".repeat(20000);
    expect(readLastLine(write(`first\n${big}\n`))).toBe(big);
  });

  test("matches the old whole-file-read result across many lines", () => {
    const lines = Array.from({ length: 5000 }, (_, i) =>
      JSON.stringify({ n: i, entry_hash: `hash_${i}` }),
    );
    const file = write(lines.join("\n") + "\n");
    const oldWay = fs
      .readFileSync(file, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .pop();
    expect(readLastLine(file)).toBe(oldWay);
    expect(JSON.parse(readLastLine(file)).entry_hash).toBe("hash_4999");
  });
});

describe("redactPII()", () => {
  test("redacts SSN", () => {
    const text = "User SSN is 123-45-6789";
    const redacted = redactPII(text);
    expect(redacted).toContain("[SSN-REDACTED]");
    expect(redacted).not.toContain("123-45-6789");
  });

  test("redacts credit card numbers", () => {
    const text = "Card: 4111111111111111";
    const redacted = redactPII(text);
    expect(redacted).toContain("[CC-REDACTED]");
    expect(redacted).not.toContain("4111111111111111");
  });

  test("redacts email addresses", () => {
    const text = "Contact user@example.com for details";
    const redacted = redactPII(text);
    expect(redacted).toContain("[EMAIL-REDACTED]");
    expect(redacted).not.toContain("user@example.com");
  });

  test("redacts phone numbers", () => {
    const text = "Call me at (555) 123-4567";
    const redacted = redactPII(text);
    expect(redacted).toContain("[PHONE-REDACTED]");
    expect(redacted).not.toContain("(555) 123-4567");
  });

  test("redacts multiple PII in one string", () => {
    const text = "SSN: 123-45-6789, Email: test@test.com, Phone: 555-123-4567";
    const redacted = redactPII(text);
    expect(redacted).toContain("[SSN-REDACTED]");
    expect(redacted).toContain("[EMAIL-REDACTED]");
    expect(redacted).toContain("[PHONE-REDACTED]");
  });

  test("passthrough on 'none' level", () => {
    setRedactionLevel("none");
    const text = "SSN: 123-45-6789";
    expect(redactPII(text)).toBe(text);
  });

  test("full redaction hashes entire text", () => {
    setRedactionLevel("full");
    const text = "Any text here with SSN: 123-45-6789";
    const redacted = redactPII(text);
    expect(redacted).toContain("...[redacted]");
    expect(redacted).not.toContain("123-45-6789");
    expect(redacted.length).toBeLessThan(text.length);
  });

  test("handles empty/null input", () => {
    expect(redactPII("")).toBe("");
    expect(redactPII(null)).toBe(null);
    expect(redactPII(undefined)).toBe(undefined);
  });

  test("preserves non-PII text", () => {
    const text = "Build a dashboard component with React";
    expect(redactPII(text)).toBe(text);
  });
});

describe("encryptEntry() + decryptEntry()", () => {
  const TEST_KEY =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 hex chars = 32 bytes

  test("encrypt then decrypt returns original", () => {
    const original = JSON.stringify({ decision: "ALLOW", score: 0 });
    const encrypted = encryptEntry(original, TEST_KEY);
    const parsed = JSON.parse(encrypted);
    expect(parsed.encrypted).toBe(true);
    expect(parsed.iv).toBeDefined();
    expect(parsed.tag).toBeDefined();
    expect(parsed.data).toBeDefined();

    const decrypted = decryptEntry(encrypted, TEST_KEY);
    expect(decrypted).toBe(original);
  });

  test("returns plaintext when no key provided", () => {
    const text = "plaintext data";
    expect(encryptEntry(text, null)).toBe(text);
  });

  test("different encryptions of same text produce different ciphertext", () => {
    const text = "same input";
    const enc1 = encryptEntry(text, TEST_KEY);
    const enc2 = encryptEntry(text, TEST_KEY);
    // Different IVs mean different ciphertext
    expect(JSON.parse(enc1).data).not.toBe(JSON.parse(enc2).data);
  });
});

describe("getRedactionLevel()", () => {
  test("returns current level", () => {
    setRedactionLevel("full");
    expect(getRedactionLevel()).toBe("full");
    setRedactionLevel("pii");
    expect(getRedactionLevel()).toBe("pii");
  });
});
