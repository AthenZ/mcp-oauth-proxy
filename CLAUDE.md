# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
This is an MCP OAuth Proxy service built with Quarkus (Java 21), designed as an OAuth 2.1/OpenID Connect authorization server. It integrates with multiple identity providers (Okta, Google, GitHub, Atlassian) and Athenz ZMS/ZTS for authorization and token exchange, with deployment to Amazon EKS via Helm charts and support for DynamoDB-based token storage.

## Build & Test Commands

### Maven Commands
- **Build**: `./mvnw clean package` or `mvn clean package`
- **Test**: `./mvnw test` or `mvn test`
- **Integration Tests**: `./mvnw verify` or `mvn verify`
- **Development Mode**: `./mvnw quarkus:dev` or `mvn quarkus:dev`
- **Native Build**: `./mvnw package -Pnative` or `mvn package -Pnative`
- **Code Coverage**: JaCoCo reports generated during test phase

### Docker Commands
```bash
# Build Docker image
docker build -f src/main/docker/Dockerfile -t mcp-oauth-proxy .
```

### Deployment
- Helm charts located in `deploy/mcp-oauth-proxy/` directory
- Deploy script: `deploy/scripts/deploy.sh`
- Helm chart includes: Deployment, Service, ConfigMap, HPA, RBAC, ServiceAccount
- Values file: `deploy/mcp-oauth-proxy/values.yaml`

## Architecture

### Core Resource Endpoints
- **TokenResource** (`src/main/java/io/athenz/mop/resource/TokenResource.java`): OAuth 2.1 token endpoint supporting `client_credentials` (mTLS) and `authorization_code` (PKCE) grant types
- **AuthorizeResource** (`src/main/java/io/athenz/mop/resource/AuthorizeResource.java`): OAuth 2.1 authorization endpoint with mandatory PKCE support
- **RegisterResource** (`src/main/java/io/athenz/mop/resource/RegisterResource.java`): Dynamic client registration endpoint (RFC 7591)
- **WellKnownResource** (`src/main/java/io/athenz/mop/resource/WellKnownResource.java`): OAuth 2.0/OIDC discovery endpoints (RFC 8414)
- **GoogleResource** (`src/main/java/io/athenz/mop/resource/GoogleResource.java`): Google OAuth callback handler
- **GithubResource** (`src/main/java/io/athenz/mop/resource/GithubResource.java`): GitHub OAuth callback handler
- **AtlassianResource** (`src/main/java/io/athenz/mop/resource/AtlassianResource.java`): Atlassian OAuth callback handler
- **AtlassianMCPResource** (`src/main/java/io/athenz/mop/resource/AtlassianMCPResource.java`): Atlassian MCP-specific integration
- **BaseResource** (`src/main/java/io/athenz/mop/resource/BaseResource.java`): Shared utilities for OAuth redirect handling

### Key Packages
- `io.athenz.mop.resource.*`: REST API endpoints and resources
- `io.athenz.mop.service.*`: Business logic services
  - `AuthorizerService`: Authorization and token exchange orchestration
  - `AuthorizationCodeService`: Authorization code generation and validation with PKCE
  - `ConfigService`: Multi-tenant configuration management
  - `RedirectUriValidator`: OAuth redirect URI validation
  - `TokenExchangeService*`: Token exchange implementations for different providers (ZTS, Okta, Google, GitHub, Atlassian)
  - `TokenExchangeServiceProducer`: Factory for token exchange service selection
- `io.athenz.mop.store.*`: Data persistence layer
  - `TokenStore`, `TokenStoreAsync`: Token storage interfaces
  - `AuthCodeStore`: Authorization code storage
  - `impl.memory.TokenStoreInMemoryImpl`: In-memory implementation
  - `impl.aws.TokenStoreDynamodbImpl`: DynamoDB implementation with encryption
  - `impl.aws.TokenStoreAsyncDynamodbImpl`: Async DynamoDB implementation
  - `DataStoreProducer`: Factory for store selection (memory vs enterprise)
- `io.athenz.mop.model.*`: Data models
  - OAuth/OIDC models: `OAuth2TokenRequest`, `OAuth2AuthorizationRequest`, `OAuth2ErrorResponse`
  - Token models: `TokenResponse`, `TokenWrapper`, `TokenRequest`, `AuthorizationCodeTokensDO`
  - Authorization models: `AuthResult`, `AuthorizationResultDO`, `AuthorizationCode`
  - Discovery models: `OpenIdConfiguration`, `OAuthAuthorizationServer`
  - Registration models: `RegisterRequest`, `RegisterResponse`
  - Configuration models: `ResourceMeta`, `TokenExchangeDO`
- `io.athenz.mop.client.*`: Athenz client producers
  - `ZMSClientProducer`: Athenz ZMS (authorization) client
  - `ZTSClientProducer`: Athenz ZTS (token service) client
- `io.athenz.mop.tls.*`: TLS/SSL certificate management
  - `CertificateReloader`: Auto-reloading certificate manager
  - `SslContextProducer`, `TrustManagerProducer`: SSL context configuration
  - `EnterpriseKeyStoreProvider`, `EnterpriseTrustStoreProvider`: Custom key/trust store providers
  - `FileSystemSecretStore`: File-based secret management
- `io.athenz.mop.secret.*`: Kubernetes secrets integration
  - `K8SSecretsProvider`: Kubernetes secret retrieval
- `io.athenz.mop.config.*`: Configuration management
  - `ResourceConfig`: Resource-to-provider mapping
  - `TokenExchangeServersConfig`: Token exchange server configuration
- `io.athenz.mop.quarkus.*`: Quarkus OIDC customizations
  - `CustomTenantConfigResolver`: Multi-tenant OIDC resolver
  - `CustomTokenStateManager`: Custom token state management
- `io.athenz.mop.util.*`: Utility classes
  - `JwtUtils`: JWT parsing and validation utilities

### Dependencies & Integrations
- **Quarkus Framework** (v3.30.6): Web framework and dependency injection
  - `quarkus-rest`: REST endpoint support
  - `quarkus-oidc`: Multi-tenant OIDC client integration
  - `quarkus-oidc-client-registration`: Dynamic client registration
  - `quarkus-tls-registry`: TLS configuration management
  - `quarkus-cache`: Token caching
  - `quarkus-security`: Security framework
  - `quarkus-hibernate-validator`: Request validation
  - `quarkus-micrometer-opentelemetry`: Metrics and observability
  - `quarkus-smallrye-health`: Health check endpoints
- **Athenz Clients** (v1.12.32):
  - `athenz-zms-java-client`: Authorization service (ZMS) integration
  - `athenz-zts-java-client`: Token service (ZTS) integration
  - `athenz-cert-refresher`: Certificate rotation support
  - `athenz-auth-core`: Core authentication utilities
- **Identity Providers**: Multi-tenant OIDC configuration for:
  - Okta (default provider)
  - Google (`quarkus.oidc.google`)
  - GitHub (`quarkus.oidc.github`)
  - Atlassian (`quarkus.oidc.atlassian`)
- **AWS SDK** (v2.41.10):
  - `dynamodb`, `dynamodb-enhanced`: Token storage
  - `kms`: Key management and encryption
  - `sts`: Security Token Service
  - `aws-database-encryption-sdk-dynamodb` (v3.9.0): Client-side encryption
  - `aws-cryptographic-material-providers` (v1.11.0): Encryption key management
- **Kubernetes Client** (v25.0.0): Secrets management and private key retrieval
- **Nimbus JOSE + JWT** (v10.7): JWT token generation, signing, and validation
- **BouncyCastle**: Enhanced cryptographic operations and PEM parsing

### Configuration
- Main config: `src/main/resources/application.yaml`
- HTTPS with configurable SSL port (TLS 1.2/1.3)
- Strong cipher suite configuration
- Certificate auto-reloading (1-hour interval)
- Optional mTLS client authentication (`client-auth: request`)
- Multi-tenant OIDC configuration for multiple identity providers
- CORS enabled for MCP inspector (localhost:6274)
- Health check endpoints at `/q/health/*`
- Access logging enabled (excluding `/q/*` paths)

### Security Features
- **Authentication**:
  - Multi-tenant OIDC integration (Okta, Google, GitHub, Atlassian)
  - mTLS client authentication for client_credentials flow (RFC 8705)
  - PKCE mandatory for authorization_code flow (OAuth 2.1)
- **Authorization**:
  - Integration with Athenz ZMS for access control decisions
  - Token exchange via Athenz ZTS and external providers
  - Subject and scope-based authorization
- **Token Security**:
  - ES256 (ECDSA) signature algorithm
  - Secure token storage with optional DynamoDB encryption
  - Authorization code single-use enforcement
  - Code challenge validation (SHA-256 only)
- **TLS/Certificate Management**:
  - Mutual TLS support
  - Certificate auto-reloading
  - Custom key/trust store providers
- **Data Protection**:
  - Client-side encryption for DynamoDB using AWS KMS
  - Kubernetes secrets integration
  - Secure credential management

### Key Endpoints

#### OAuth 2.1 / OIDC Endpoints
- `GET /.well-known/openid-configuration`: OpenID Connect discovery document
- `GET /.well-known/oauth-authorization-server`: OAuth 2.0 Authorization Server metadata (RFC 8414)
- `GET /authorize`: OAuth 2.1 authorization endpoint (requires authentication, PKCE mandatory)
- `POST /token`: OAuth 2.1 token endpoint
  - `client_credentials` grant with mTLS authentication (RFC 8705)
  - `authorization_code` grant with PKCE (RFC 7636 / OAuth 2.1)
- `POST /register`: Dynamic client registration (RFC 7591)

#### Provider-Specific OAuth Callbacks
- `GET /google/authorize`: Google OAuth callback handler
- `GET /github/authorize`: GitHub OAuth callback handler
- `GET /atlassian/authorize`: Atlassian OAuth callback handler

#### Health & Monitoring
- `GET /q/health/*`: Health check endpoints

### OAuth 2.1 / OIDC Support

#### Supported Grant Types
- **`authorization_code`**: Authorization code flow with mandatory PKCE (RFC 7636)
  - Code challenge method: `S256` only (plain deprecated in OAuth 2.1)
  - Single-use authorization codes
  - Redirect URI validation
  - State parameter for CSRF protection
- **`client_credentials`**: Client credentials flow with mTLS authentication (RFC 8705)
  - Client authentication via X.509 certificates
  - Subject extracted from certificate CN
  - Resource parameter required (RFC 8707)

#### Authentication Methods
- `tls_client_auth`: mTLS client authentication (RFC 8705) for client_credentials
- `none`: No authentication for authorization_code (PKCE provides security)
- `client_secret_post`: Client secret in request body (OIDC providers)

#### Token Types & Algorithms
- **Signature Algorithm**: ES256 (ECDSA with P-256 and SHA-256)
- **Response Types**: `code`, `token`, `id_token token`
- **Scopes**: `openid`, `offline_access` (provider-specific scopes also supported)
- **Claims**: `sub`, `aud`, `iss`, `exp`, `iat`

#### Standards Compliance
- OAuth 2.1 authorization code flow with PKCE
- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7591: Dynamic Client Registration Protocol
- RFC 7636: PKCE (Proof Key for Code Exchange)
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication
- RFC 8707: Resource Indicators for OAuth 2.0
- OpenID Connect Discovery 1.0

#### NOT Supported
- Token introspection endpoint
- Token revocation endpoint
- Implicit and password grant types (deprecated in OAuth 2.1)
- Plain PKCE code challenge method (deprecated in OAuth 2.1)

### Data Storage Options

#### Memory Store (Development/Testing)
- In-memory token and authorization code storage
- No persistence across restarts
- Selected via `@MemoryStoreQualifier`

#### Enterprise Store (Production)
- DynamoDB-based token storage with encryption
- Client-side encryption using AWS KMS
- Asynchronous operations supported
- Configured via `@EnterpriseStoreQualifier`
- Table structure defined in `TokenTableAttribute`

### Testing
- **Frameworks**: JUnit 5, Mockito, REST Assured, Quarkus JUnit5 Mockito
- **Coverage**: JaCoCo plugin configured for code coverage reports
- **Integration Tests**: Disabled by default (`skipITs=true`), enabled in native profile
- **Test Resources**: Located in `src/test/`
- **Test Structure**:
  - Unit tests for all resources, services, models, stores
  - Mock-based testing for external dependencies (ZMS, ZTS, OIDC providers)
  - REST Assured for API endpoint testing