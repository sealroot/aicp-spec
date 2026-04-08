# Contributing to AICP

Thank you for your interest in the Agent Identity and Capability Protocol. We welcome contributions from the community.

## Ways to Contribute

### Specification Feedback

- Open an issue describing the concern, ambiguity, or improvement.
- Reference the specific section and version of the spec.
- Propose concrete wording changes when possible.

### Security Review

- If you find a security vulnerability in the protocol design, please report it responsibly via email to security@sealroot.com.
- Do NOT open public issues for security vulnerabilities.

### Reference Implementation

- Bug fixes and improvements to the reference SDKs are welcome.
- New language SDKs should conform to the spec and pass the conformance test suite.

### Documentation

- Corrections, clarifications, and translations of the specification.
- Tutorials and guides for implementers.

## Process

1. **Open an issue** describing the change you'd like to make.
2. **Discuss** the approach with maintainers.
3. **Submit a pull request** referencing the issue.
4. **Review** — all PRs require at least one maintainer review.

## Specification Changes

Changes to the core protocol specification (AIC, ACT, SIE) follow a higher bar:

- MUST include a rationale section explaining why the change is needed.
- MUST include a backward compatibility analysis.
- MUST NOT break existing implementations without a version bump.
- SHOULD include updates to the threat model if the security surface changes.

## Code of Conduct

Be respectful, constructive, and professional. We are building critical security infrastructure — precision and rigor matter more than speed.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0 (for code) and CC-BY 4.0 (for specification documents).
