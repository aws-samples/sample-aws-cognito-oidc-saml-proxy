# Data model

The gateway uses two Amazon DynamoDB tables with composite keys (`PK`, `SK`), both encrypted
with the AWS KMS encryption key:

- **Config table**: tenants, identity sources, applications, SAML/OIDC settings, claim and
  role mappings, and signing certificates. The `entityId-index` GSI resolves a SAML entity
  ID to its tenant and application.
- **Session table**: short-lived protocol state and a 24-hour copy of audit steps. Items
  expire through DynamoDB TTL; the permanent audit record is in Amazon CloudWatch Logs.

```mermaid
classDiagram
    direction LR

    class Tenant {
        +slug : string
        +displayName : string
        +plan : string
        +status : string
        +kmsKeyId : string
        +maxApps : int
        +defaultSignResponse : bool
        +defaultNameIdFormat : string
        +defaultScopes : string[]
    }

    class IdentitySource {
        +id : string
        +displayName : string
        +type : string
        +poolId : string
        +region : string
        +domain : string
        +clientId : string
        +status : string
    }

    class Application {
        +id : string
        +displayName : string
        +protocol : string
        +sourceId : string
        +status : string
    }

    class SAMLConfig {
        +entityId : string
        +acsUrl : string
        +acsUrls : string[]
        +nameIdFormat : string
        +nameIdSource : string
        +signResponse : bool
        +signAssertion : bool
        +sloUrl : string
    }

    class OIDCConfig {
        +redirectURIs : string[]
        +grantTypes : string[]
        +scopes : string[]
        +tokenEndpointAuthMethod : string
        +idTokenLifetimeSec : int
    }

    class ClaimMapping {
        +name : string
        +sourceType : string
        +sourceAttribute : string
        +targetAttribute : string
        +required : bool
        +defaultValue : string
    }

    class RoleMapping {
        +cognitoGroup : string
        +mappedValue : string
    }

    class FlowStep {
        +flowId : string
        +sequence : int
        +stepType : string
        +spEntityId : string
        +userId : string
        +timestamp : datetime
        +payload : map
    }

    Tenant "1" --> "*" IdentitySource : sources
    Tenant "1" --> "*" Application : apps
    Application "1" --> "0..1" SAMLConfig : saml
    Application "1" --> "0..1" OIDCConfig : oidc
    Application "1" --> "*" ClaimMapping : claims
    Application "1" --> "*" RoleMapping : roles
    Application "*" --> "1" IdentitySource : authenticates via
    Tenant "1" --> "*" FlowStep : audit trail
```

## DynamoDB key design

| Table | Entity | PK | SK |
|-------|--------|----|----|
| Config | Tenant config | `TENANT#{slug}` | `CONFIG` |
| Config | Identity source | `TENANT#{slug}` | `SOURCE#{id}` |
| Config | Application | `TENANT#{slug}` | `APP#{id}` |
| Config | SAML config | `TENANT#{slug}` | `APP#{id}#SAML` |
| Config | OIDC config | `TENANT#{slug}` | `APP#{id}#OIDC` |
| Config | Claim mapping | `TENANT#{slug}` | `APP#{id}#CLAIM#{name}` |
| Config | Role mapping | `TENANT#{slug}` | `APP#{id}#ROLE#{group}` |
| Config | Signing cert | `SYSTEM#CONFIG` | `SYSTEM#SIGNING_CERT` (also `_NEXT`, `_BACKUP`) |
| Session | Audit step | `TENANT#{slug}#FLOW#{flowId}` | `STEP#{timestamp}#{random}` |
| Session | Replay guard | `REPLAY#{requestId}` | `_` |
| Session | SAML session participant | `SESSION#{sessionIndex}` | `SP#{entityId}` |
| Session | Pending custom login | `PENDINGLOGIN#{flowId}` | `_` |
| Session | OIDC auth request | `AUTHREQ#{id}` | `META` |
| Session | OIDC authorization code | `AUTHCODE#{code}` | `META` |
| Session | OIDC access token | `TOKEN#{id}` | `META` |
| Session | OIDC refresh token | `REFRESHTOKEN#{token}` | `META` |
| Session | OIDC session index | `OIDCSESSION#t:{tenant}#u:{sub}#c:{clientId}` | `TOKEN#{tokenRef}` |

The `entityId-index` GSI keys on `GSI1PK` = `ENTITY#{slug}#{entityId}` and
`GSI1SK` = `TENANT#{slug}`. Session items expire through the `ttl` attribute.
