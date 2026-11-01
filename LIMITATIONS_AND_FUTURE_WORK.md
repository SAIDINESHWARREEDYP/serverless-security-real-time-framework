# PHASE 13 — Architectural Limitations & Future Research Directions

## 1. Identified Architectural Limitations

1. **In-Memory Cache vs. Distributed Cluster State**:
   - In horizontally autoscaled serverless container environments (e.g. 100+ concurrent worker instances), rate-limiting and temporary MFA challenge maps benefit from distributed Redis/KV caches to prevent cache divergence across distinct nodes.
2. **Regex-Based Payload Inspection Complexity**:
   - While regular expressions execute in $< 0.25\text{ ms}$, highly polymorphic adversarial payloads with nested multi-layer base64/hex encoding require recursive decoding pipelines to detect obfuscated payloads.
3. **Hardware Token (FIDO2 / WebAuthn) Integration**:
   - Currently, factor 2 authentication implements RFC 6238 TOTP (Google Authenticator, Microsoft Authenticator) and SMS OTP. Integrating hardware security keys (YubiKey / WebAuthn) would achieve FIPS 140-3 Level 4 assurance.

---

## 2. Future Work & Enhancements

1. **Dynamic Markov Graph Auto-Discovery**:
   - Automatically infer valid function invocation sequence graphs from OpenAPI / AsyncAPI specifications or historical trace graphs using continuous Bayesian learning.
2. **Zero-Knowledge Proofs for Auditing**:
   - Enable external third-party compliance auditors to verify hash-chain validity and absence of tampering without exposing proprietary operational payload metadata.
3. **Distributed eBPF Kernel Tracing**:
   - Extend the serverless edge verification proxy with Linux eBPF probes for sub-microsecond system call interception in containerized serverless runtimes (AWS Firecracker / gVisor).
