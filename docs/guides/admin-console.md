# Administration console

The admin console is a React/TypeScript single-page app (Cloudscape Design System) served
from S3 via CloudFront and authenticated with Amazon Cognito. Admins use it to manage
tenants, identity sources, applications, and claim/role mappings.

!!! note
    Console access requires your Cognito user to be in the `Admins` or `Operators` group.
    See [Post-install configuration](../deployment/post-install.md).

## Applications

Register and configure SAML or OIDC applications, including per-app endpoints, ACS URLs,
NameID formats, redirect URIs, and token lifetimes.

![Application detail](../images/admin-app-detail.png)

## Claim mappings

Map source attributes and `cognito:groups` to per-application SAML attributes or OIDC
claims — declaratively, without writing Lambda code.

![Claim mappings](../images/admin-claim-mappings.png)

## Integration details

Each application surfaces the exact metadata / discovery URLs and settings needed to wire up
the relying party.

![Integration details](../images/admin-integration.png)

## Results

A completed SAML SSO and an OIDC token exchange, driven through the demo apps:

![SAML SSO result](../images/saml-sso-result.png)

![OIDC token result](../images/oidc-token-result.png)
