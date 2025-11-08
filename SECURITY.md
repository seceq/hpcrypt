# Security Policy

## Reporting a Vulnerability

The HPCrypt team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by email to:

**security@[your-domain].com** (TODO: Replace with actual security contact email)

You should receive a response within 48 hours. If for some reason you do not, please follow up to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., timing attack, memory leak, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage & Validation**: Within 7 days
- **Fix Development**: Depends on severity (1-30 days)
- **Public Disclosure**: After fix is released and users have time to update

### Disclosure Policy

- We will acknowledge receipt of your vulnerability report within 48 hours
- We will provide an estimated timeline for a fix within 7 days
- We will notify you when the vulnerability is fixed
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

**Note**: As HPCrypt is currently in pre-1.0 development, we support only the latest version. Once we release 1.0, we will maintain security updates for stable versions.

## Security Considerations

### Cryptographic Implementation

HPCrypt is implemented in 100% safe Rust and aims for constant-time operations where cryptographically relevant. However:

- ⚠️ **HPCrypt has not yet undergone independent security audit**
- ⚠️ **Constant-time behavior has not been verified with timing analysis tools**
- ⚠️ **Not recommended for use in high-security environments without additional audit**

### Known Limitations

1. **No Independent Audit**: The library has not been independently audited by professional cryptographers
2. **Constant-Time**: While designed for constant-time execution, this has not been verified with tools like dudect or ctgrind
3. **Side-Channel Resistance**: Side-channel resistance has not been formally verified
4. **Assembly Inspection**: Generated assembly has not been thoroughly inspected for all platforms

### Responsible Use

- ✅ **DO** use for learning, experimentation, and non-critical applications
- ✅ **DO** use in controlled environments where you understand the risks
- ✅ **DO** contribute to testing and validation efforts
- ⚠️ **USE WITH CAUTION** in production environments
- ❌ **DO NOT** use for life-critical systems without professional audit
- ❌ **DO NOT** use for financial systems without professional audit
- ❌ **DO NOT** assume constant-time behavior without verification

### Secure Usage Guidelines

#### Key Material Handling

```rust
// ✅ GOOD: Use strong random sources for keys
use getrandom::getrandom;

let mut key = [0u8; 32];
getrandom(&mut key)?;

// ❌ BAD: Don't use weak randomness
let key = [0u8; 32];  // All zeros - not secure!
```

#### Nonce Usage

```rust
// ✅ GOOD: Never reuse nonces with the same key
let nonce = generate_random_nonce();  // New nonce each time

// ❌ BAD: Reusing nonces breaks security
let nonce = [0u8; 12];  // Same nonce every time - DANGEROUS!
```

#### Key Derivation

```rust
// ✅ GOOD: Use proper KDFs for password hashing
use hpcrypt_kdf::{Argon2id, Params};

let hash = Argon2id::hash(password, salt, &Params::default())?;

// ❌ BAD: Don't hash passwords with regular hash functions
let hash = sha256(password);  // Vulnerable to brute force!
```

#### ECDH Validation

```rust
// ✅ GOOD: Validate points before use
let point = decode_point(public_key)?;
point.validate()?;  // Check on-curve, in correct group
let shared = ecdh(&private_key, &point)?;

// ❌ BAD: Trust untrusted input
let shared = ecdh(&private_key, untrusted_point)?;  // Vulnerable to invalid point attacks!
```

## Security Roadmap

### Planned Security Enhancements

- [ ] **Q1 2026**: Constant-time verification (dudect, ctgrind)
- [ ] **Q2 2026**: Professional security audit
- [ ] **Q3 2026**: Fuzzing campaign (integration with OSS-Fuzz)
- [ ] **Q4 2026**: Formal verification (selected components)
- [ ] **2027**: FIPS 140-3 certification (if demand exists)

### Current Security Features

- ✅ 100% safe Rust (no unsafe code)
- ✅ Designed for constant-time operations (unverified)
- ✅ Uses `subtle` crate for constant-time primitives
- ✅ Key material zeroization (via `zeroize` crate)
- ✅ Extensive test coverage (156/156 tests passing)
- ✅ RFC compliance (X25519, Ed25519, ChaCha20-Poly1305, AES-GCM)

## Threat Model

### In-Scope Threats

We aim to protect against:

- ✅ Timing attacks (constant-time operations)
- ✅ Memory disclosure (key zeroization)
- ✅ Invalid point attacks (point validation)
- ✅ Weak random number generation (proper CSPRNG usage)
- ✅ Nonce reuse (documentation, API design)

### Out-of-Scope Threats

We do not currently protect against:

- ⚠️ Physical attacks (side-channel analysis with oscilloscopes, etc.)
- ⚠️ Fault injection attacks
- ⚠️ Advanced persistent threats with physical access
- ⚠️ Quantum computers (except with post-quantum algorithms)

## Bug Bounty

**Status**: Not currently available

We may establish a bug bounty program in the future. For now, we rely on responsible disclosure and community security research.

## Security Hall of Fame

We will acknowledge security researchers who responsibly disclose vulnerabilities:

<!--
Contributors will be listed here after responsible disclosure:
- [Researcher Name] - [Vulnerability Type] - [Date]
-->

*No vulnerabilities have been reported yet.*

## References

### Cryptographic Standards

- [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf): Digital Signature Standard
- [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf): Elliptic Curve Cryptography
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748): Elliptic Curves for Security (X25519)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Edwards-Curve Digital Signature Algorithm (Ed25519)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): ChaCha20-Poly1305 AEAD
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106): Argon2 Memory-Hard Function

### Security Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [SafeCurves](https://safecurves.cr.yp.to/): Security criteria for elliptic curves

## Contact

- **Security Issues**: security@[your-domain].com (TODO: Replace)
- **General Issues**: [GitHub Issues](https://github.com/[your-username]/hpcrypt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/[your-username]/hpcrypt/discussions)

---

**Last Updated**: October 21, 2025
**Version**: 1.0
