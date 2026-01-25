# MCP OAuth Proxy

A secure OAuth 2.1 / OpenID Connect authorization server that acts as a unified proxy for multiple identity providers. Built with Quarkus, it simplifies authentication and authorization for Model Context Protocol (MCP) servers and other applications by providing a single integration point for Google, GitHub, Atlassian, Okta, and custom identity providers.

## What Does This Do?

MCP OAuth Proxy solves the challenge of managing multiple OAuth providers and complex authorization flows. Instead of integrating each identity provider separately, MCP client connects to this proxy which:

- **Handles OAuth 2.1 flows** - Supports both authorization code (with PKCE) and client credentials grants
- **Unifies multiple providers** - Single endpoint for Google, GitHub, Atlassian, Okta, and more
- **Enforces authorization** - Integrates with Athenz for fine-grained access control decisions
- **Manages tokens securely** - Stores and exchanges tokens with encryption support (DynamoDB + KMS)
- **Provides mTLS security** - Certificate-based client authentication for machine-to-machine flows

## Key Features

- OAuth 2.1 compliant authorization server
- Multi-tenant OIDC provider support
- Dynamic client registration (RFC 7591)
- Mandatory PKCE for authorization code flows
- mTLS client authentication support
- Token exchange with multiple authorization servers
- Kubernetes-native with Helm deployment
- Enterprise-grade token storage with DynamoDB encryption

## Documentation

- [CLAUDE.md](CLAUDE.md) - Detailed technical documentation and architecture
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines and contribution process
- [SECURITY.md](SECURITY.md) - Security policies and vulnerability reporting
