# Data model

All entities share a single Amazon DynamoDB table using composite keys (`PK`, `SK`) with
two GSIs for entity ID lookup and user-flow queries.

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

| Entity | PK | SK |
|--------|----|----|
| Tenant config | `TENANT#{slug}` | `CONFIG` |
| Identity source | `TENANT#{slug}` | `SOURCE#{id}` |
| Application | `TENANT#{slug}` | `APP#{id}` |
| SAML config | `TENANT#{slug}` | `APP#{id}#SAML` |
| OIDC config | `TENANT#{slug}` | `APP#{id}#OIDC` |
| Claim mapping | `TENANT#{slug}` | `APP#{id}#CLAIM#{name}` |
| Role mapping | `TENANT#{slug}` | `APP#{id}#ROLE#{group}` |
| Audit step | `FLOW#{flowId}` | `STEP#{sequence}` |
| Replay guard | `REPLAY#{requestId}` | `_` |
| Access token | `OIDC#TOKEN` | `ACCESS#{hash}` |
| Signing cert | `SYSTEM#CONFIG` | `SYSTEM#SIGNING_CERT` |

The config table is encrypted at rest with the symmetric KMS encryption key. A second
DynamoDB table holds short-lived flow/session state, expired automatically via DynamoDB TTL.
