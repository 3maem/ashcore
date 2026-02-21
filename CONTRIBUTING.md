# Contributing to ASH

Thank you for your interest in contributing to ASH.

Whether you fix a bug, improve documentation, suggest an idea, or submit code — you are helping make security better for everyone.

We welcome contributions of **any size**.

---

## Quick Start

1. Fork the repository
2. Create a branch
3. Make your changes
4. Run tests
5. Open a Pull Request

---

## Ways to Contribute

- Code (features, fixes, refactors)
- Bug reports
- Tests
- Documentation improvements
- Ideas and discussions
- Security reviews
- Performance optimizations

---

## Development Setup

### Rust (ASH)

```bash
cargo build
cargo test
```

### Node.js SDK

```bash
cd packages/ash-node-sdk
npm install
npm run build
npm run test
```

---

## Development Guidelines

### Code Style
- Follow the existing style in each SDK
- Keep functions small and readable
- Prefer clarity over cleverness

### Testing
- Add tests for new behavior
- Do not break existing tests
- All SDKs must pass 134/134 conformance vectors

### Documentation
If you add a feature, update documentation as well.

---

## Commit Messages

We follow **Conventional Commits**.

### Examples

```
feat: add request signing middleware
fix: prevent replay attack edge case
docs: update README examples
test: add verification tests
refactor: simplify hash logic
```

### Format

```
type: short description
```

### Common types
- `feat`
- `fix`
- `docs`
- `refactor`
- `test`
- `chore`

---

## Security Contributions

ASH is a security-focused project.

If you discover a vulnerability:

**Do NOT open a public issue.**

Email us privately at: **security@ashcore.com**

We practice responsible disclosure and will respond quickly.

---

## License

By contributing, you agree that your contributions will be licensed under the **Apache License 2.0**.

---

## Thank You

Every line of code, every typo fix, and every idea helps.

Thanks for helping make the web safer with ASH.
