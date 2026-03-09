# Contributing to CORD Engine

Thanks for your interest in contributing to CORD! This is a security-critical project — contributions that strengthen AI safety are especially welcome.

## Getting Started

```bash
git clone https://github.com/zanderone1980/artificial-persistent-intelligence.git
cd artificial-persistent-intelligence
npm install
npm test          # 482 tests across 13 suites
npx cord-engine demo  # Watch it block attacks live
```

## How to Contribute

1. **Security vulnerabilities** — Do NOT open a public issue. Email alex@zanderpinkdesign.com. See [SECURITY.md](SECURITY.md).
2. **Bug reports** — Open a GitHub issue with reproduction steps.
3. **New attack patterns** — Add to the red team test suite (`tests/redteam.test.js`).
4. **Framework adapters** — Add support for new AI frameworks in `cord/frameworks/`.
5. **Documentation** — Improvements to README, inline docs, or usage examples.

## Development

```bash
# Run all tests
npm test

# Run specific test suite
npx jest cord/cord.test.js --verbose

# Run red team validation
npx jest tests/redteam.test.js --verbose

# Run VIGIL scanner tests
npx jest vigil/ --verbose
```

## Code Style

- Zero external dependencies — all logic is self-contained
- Every new evaluation dimension needs test coverage
- Red team tests must maintain 100% block rate
- JSDoc comments on all public APIs

## Architecture

```
cord/           # Core CORD evaluation engine
vigil/          # VIGIL threat scanner (proactive defense)
cord_engine/    # Python bridge
tests/          # Integration + red team tests
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
