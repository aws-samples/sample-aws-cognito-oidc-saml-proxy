import type { HelpContent } from '../contexts/HelpPanelContext';

// Contextual help for the simpler pages: Dashboard, Applications list,
// Register wizard, Analytics, Audit log, Protocol debugger.

export const dashboardOverviewHelp: HelpContent = {
  header: <h2>Overview</h2>,
  content: (
    <div>
      <p>At-a-glance health of the federation gateway.</p>
      <h3>Metrics</h3>
      <ul>
        <li><strong>Identity sources</strong> — Cognito user pools configured as IdP backends.</li>
        <li><strong>Applications</strong> — registered SAML/OIDC relying parties.</li>
        <li><strong>Certificate expiry</strong> — days remaining on the active signing certificate (rotate before it lapses).</li>
        <li><strong>Total authentications</strong> — recent sign-in volume across all apps.</li>
      </ul>
      <p>Each metric links to the page where you can act on it.</p>
    </div>
  ),
};

export const dashboardEventsHelp: HelpContent = {
  header: <h2>Recent events</h2>,
  content: (
    <div>
      <p>
        The latest authentication flow events across the gateway. Each row is one step in a
        flow (initiation, completion, errors). Use the <strong>Audit log</strong> for full
        history and filtering, or the <strong>Protocol debugger</strong> to trace a single flow ID.
      </p>
    </div>
  ),
};

export const applicationsPageHelp: HelpContent = {
  header: <h2>Applications</h2>,
  content: (
    <div>
      <p>
        All registered relying parties (SAML SPs and OIDC RPs) for this tenant. Each binds to an
        identity source and receives assertions/tokens from the gateway.
      </p>
      <h3>Actions</h3>
      <ul>
        <li><strong>Register new</strong> — launch the guided wizard to add an application.</li>
        <li>Open an application to edit its protocol settings, mappings, custom login, and integration details.</li>
        <li><strong>Disable</strong> pauses issuance without deleting; <strong>Delete</strong> removes the app and its mappings.</li>
      </ul>
    </div>
  ),
};

export const registerAppHelp: HelpContent = {
  header: <h2>Register an application</h2>,
  content: (
    <div>
      <p>A guided wizard to add a SAML or OIDC application.</p>
      <h3>Steps</h3>
      <ol>
        <li><strong>Configuration</strong> — choose the protocol and bind an identity source. For SAML you can import the SP's metadata to prefill entity ID and ACS URL.</li>
        <li><strong>Settings</strong> — name, NameID/lifetimes, signing options, and an optional custom login page.</li>
        <li><strong>Mappings</strong> — the claims/attributes and role mappings released to the app.</li>
        <li><strong>Preview &amp; Summary</strong> — review the generated assertion/token and confirm.</li>
      </ol>
      <p>Defaults come from the tenant's Protocol Defaults (Gateway configuration) and can be overridden per app later.</p>
    </div>
  ),
};

export const analyticsPageHelp: HelpContent = {
  header: <h2>Analytics</h2>,
  content: (
    <div>
      <p>Authentication metrics across the gateway.</p>
      <h3>Current metrics</h3>
      <ul>
        <li><strong>Total Applications</strong> — registered relying parties (links to Applications).</li>
        <li><strong>Total Authentications</strong> — sign-in count for the selected window (default: last 7 days; links to the Audit log).</li>
      </ul>
      <p>
        Use the date range control to change the window. Detailed time-series charts and
        per-application breakdowns are planned.
      </p>
    </div>
  ),
};

export const auditLogPageHelp: HelpContent = {
  header: <h2>Audit log</h2>,
  content: (
    <div>
      <p>
        A chronological trace of authentication flow events. Each row is one <strong>step</strong>
        of a flow; steps that share a <strong>Flow ID</strong> belong to the same authentication.
        Click a Flow ID to see the full step-by-step trace for that flow.
      </p>
      <h3>Columns</h3>
      <ul>
        <li><strong>Timestamp</strong> — when the step occurred.</li>
        <li><strong>Flow ID</strong> — groups all steps of one authentication (open it for the full trace).</li>
        <li><strong>Event type</strong> — the step, e.g. <code>sso_initiated</code>, <code>sso_complete</code>, <code>sso_token_auth</code>, <code>oidc_login_complete</code>, <code>idp_initiated</code>.</li>
        <li><strong>User / Application</strong> — the subject and target relying party.</li>
      </ul>
      <p>For deep inspection of a single flow, use the <strong>Protocol debugger → Flow Trace</strong>.</p>
    </div>
  ),
};

export const debuggerPageHelp: HelpContent = {
  header: <h2>Protocol debugger</h2>,
  content: (
    <div>
      <p>Developer tools for troubleshooting federation.</p>
      <h3>Decode Assertion</h3>
      <p>
        Paste a base64-encoded SAML assertion to decode and inspect its XML — verify the
        subject, attributes, conditions, and signing without leaving the console.
      </p>
      <h3>Flow Trace</h3>
      <p>
        Enter a <strong>Flow ID</strong> (from the Audit log) to replay the ordered steps of that
        authentication, with timestamps and success/error status for each — the fastest way to
        see where a failing SSO broke.
      </p>
    </div>
  ),
};
