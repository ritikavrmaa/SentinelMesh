# SentinelMesh

SentinelMesh is a lightweight Zero-Trust service mesh for decentralized APIs. It verifies every service-to-service request using cryptographic identity, JWT access tokens, Ed25519 proof-of-possession, replay protection, route policies, token revocation, contextual authorization, and dynamic re-authentication.

## Problem Statement

Internal microservice traffic is often trusted after initial authentication. If one token or service is compromised, an attacker may move laterally across protected APIs.

SentinelMesh applies Zero-Trust principles to every request:

- Verify service identity
- Validate token audience
- Check route authorization
- Detect replay attacks
- Detect payload tampering
- Block revoked or expired tokens
- Require re-authentication for high-risk transactions

## Architecture

```text
User Service
    |
    v
Zero-Trust Proxy
    |
    v
Order Service
    |
    v
Zero-Trust Proxy
    |
    v
Payment Service
    |
    v
Zero-Trust Proxy
    |
    v
Database Service