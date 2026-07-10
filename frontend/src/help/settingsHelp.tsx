import type { HelpContent } from '../contexts/HelpPanelContext';

// Contextual help for the Gateway Configuration (Settings) page.

export const settingsPageHelp: HelpContent = {
  header: <h2>Gateway configuration</h2>,
  content: (
    <div>
      <p>
        Tenant-wide settings: the tenant profile and quotas, the default protocol behavior
        applied to newly registered applications, and read-only infrastructure information.
      </p>
      <p>
        Protocol defaults seed new applications — changing them does not retroactively alter
        existing apps, which keep their own per-app settings.
      </p>
    </div>
  ),
};

export const tenantProfileHelp: HelpContent = {
  header: <h2>Tenant profile</h2>,
  content: (
    <div>
      <h3>Fields</h3>
      <dl>
        <dt><strong>Display name</strong></dt>
        <dd>Friendly name for this tenant.</dd>
        <dt><strong>Plan</strong></dt>
        <dd>Subscription plan (read-only).</dd>
        <dt><strong>Max applications</strong></dt>
        <dd>Quota on how many applications this tenant may register.</dd>
        <dt><strong>Max authentications per month</strong></dt>
        <dd>Monthly authentication quota for usage tracking/limits.</dd>
      </dl>
      <p>Quotas are guardrails for the tenant; adjust them to match the plan.</p>
    </div>
  ),
};

export const protocolDefaultsHelp: HelpContent = {
  header: <h2>Protocol defaults</h2>,
  content: (
    <div>
      <p>Defaults applied when a new application is created. Per-app settings override these.</p>
      <h3>SAML defaults</h3>
      <dl>
        <dt><strong>Session duration</strong></dt>
        <dd>Default assertion session length (seconds) for new SAML apps.</dd>
        <dt><strong>Sign Response / Sign Assertion</strong></dt>
        <dd>Whether new SAML apps sign the response and/or assertion by default.</dd>
        <dt><strong>NameID format</strong></dt>
        <dd>Default subject identifier format for new SAML apps.</dd>
      </dl>
      <h3>OIDC defaults</h3>
      <dl>
        <dt><strong>ID / Access token lifetime</strong></dt>
        <dd>Default token validity (seconds) for new OIDC apps.</dd>
      </dl>
    </div>
  ),
};

export const gatewayInfoHelp: HelpContent = {
  header: <h2>Gateway information</h2>,
  content: (
    <div>
      <p>Read-only infrastructure details for this deployment, useful for support and audits.</p>
      <h3>Fields</h3>
      <dl>
        <dt><strong>KMS signing key ID</strong></dt>
        <dd>The primary AWS KMS key used to sign assertions/tokens. The private key never leaves KMS.</dd>
        <dt><strong>Backup KMS key ID</strong></dt>
        <dd>
          The optional second KMS key backing the backup certificate. Present only when a backup
          key is provisioned (enables a true key roll on promotion).
        </dd>
        <dt><strong>Base URL / endpoints</strong></dt>
        <dd>The gateway's public base URL from which tenant-scoped SAML/OIDC endpoints are derived.</dd>
      </dl>
    </div>
  ),
};
