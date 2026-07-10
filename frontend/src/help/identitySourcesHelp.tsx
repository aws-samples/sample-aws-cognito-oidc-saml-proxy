import type { HelpContent } from '../contexts/HelpPanelContext';

// Contextual help for the Identity Sources list + detail pages.

export const identitySourcesPageHelp: HelpContent = {
  header: <h2>Identity sources</h2>,
  content: (
    <div>
      <p>
        An <strong>identity source</strong> is an Amazon Cognito user pool the gateway uses to
        authenticate end users. Applications bind to a source; when a user signs in, the source
        verifies them and the gateway issues the assertion/token to the app.
      </p>
      <h3>What a source provides</h3>
      <ul>
        <li>The user pool (and its app client) that performs authentication.</li>
        <li>The issuer the gateway trusts when verifying Cognito ID tokens (e.g. for token-based / custom-login flows — the token's audience must match the source's app client).</li>
        <li>The attributes available to claim mappings (email, name, groups, custom attributes).</li>
      </ul>
      <h3>Onboarding</h3>
      <p>
        Register a source by supplying its pool ID, region, app client, and (for cross-account
        pools) an IAM role the gateway can assume. The onboarding flow validates connectivity
        before activating the source.
      </p>
    </div>
  ),
};

export const sourceDetailHelp: HelpContent = {
  header: <h2>Identity source</h2>,
  content: (
    <div>
      <p>Configuration for one Cognito user pool used as an identity source.</p>
      <h3>Fields</h3>
      <dl>
        <dt><strong>Pool ID / Region</strong></dt>
        <dd>The Cognito user pool and its region — together they form the token issuer the gateway trusts.</dd>
        <dt><strong>App client ID</strong></dt>
        <dd>The public app client used for sign-in. Token-based flows require the ID token's <code>aud</code> to equal this client.</dd>
        <dt><strong>Domain</strong></dt>
        <dd>The Cognito Hosted UI / OAuth domain used for the redirect-based login flow.</dd>
        <dt><strong>Role ARN</strong> (cross-account)</dt>
        <dd>An IAM role the gateway assumes to reach a pool in another AWS account. Empty for same-account pools using the public-client PKCE path.</dd>
        <dt><strong>Status</strong></dt>
        <dd>Whether the source is active and available to back applications.</dd>
      </dl>
    </div>
  ),
};

export const sourceAppsHelp: HelpContent = {
  header: <h2>Applications using this source</h2>,
  content: (
    <div>
      <p>
        The applications bound to this identity source. Each authenticates its users against
        this Cognito pool. Deleting or disabling a source affects every application listed here,
        so review this list before changing the source.
      </p>
    </div>
  ),
};
