import type { HelpContent } from '../contexts/HelpPanelContext';

// Contextual help for the application "Mappings" tab. Content is intentionally
// accurate to the gateway's actual behavior (see internal/saml/assertion_maker.go):
// the three mapping types, the Required/Default semantics, and the fact that the
// gateway imposes no claim caps of its own (the limits shown are Cognito's).

const limitsTableStyle: React.CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
  fontSize: '0.85rem',
  marginTop: '0.5rem',
};
const cellStyle: React.CSSProperties = {
  border: '1px solid #d1d5db',
  padding: '6px 8px',
  textAlign: 'left',
  verticalAlign: 'top',
};

export const claimMappingsHelp: HelpContent = {
  header: <h2>Claim mappings</h2>,
  content: (
    <div>
      <p>
        Claim mappings define the extra attributes (SAML) or claims (OIDC) the gateway
        releases to <em>this</em> application, in addition to the standard NameID/subject.
        Each row maps a <strong>Source</strong> to a <strong>Target</strong> claim using a
        <strong> Type</strong> that controls how the source is interpreted.
      </p>

      <h3>Mapping types</h3>
      <dl>
        <dt><strong>attribute</strong></dt>
        <dd>
          Copies the value of a Cognito user attribute / token field named in
          <strong> Source</strong> (e.g. <code>email</code>, <code>given_name</code>,
          <code>family_name</code>, <code>name</code>, <code>sub</code>, <code>username</code>,
          or a custom attribute) into the Target claim. If the source resolves empty, the
          <strong> Default value</strong> is used when one is set.
        </dd>
        <dt><strong>static</strong></dt>
        <dd>
          Ignores Source. Always emits the <strong>Default value</strong> as a fixed constant
          for every user — useful for tagging all assertions with a constant (e.g. an
          environment or tenant marker).
        </dd>
        <dt><strong>groupMapping</strong></dt>
        <dd>
          Ignores Source. Emits one value per Cognito group the user belongs to, translated
          through the <strong>Role Mappings</strong> table below (Cognito group → mapped
          value). Groups with no role mapping are skipped. Use this for role/entitlement
          claims.
        </dd>
      </dl>

      <h3>Required</h3>
      <p>
        Marks the claim as mandatory (intent/documentation). Note: in the current build this
        is <strong>not enforced</strong> at sign-in — a claim whose source resolves empty and
        has no Default value is simply omitted from the assertion. To guarantee a claim is
        always present, set a <strong>Default value</strong>.
      </p>

      <h3>Default value</h3>
      <p>
        Acts as a fallback for <code>attribute</code> mappings when the source is empty, and
        as the constant value for <code>static</code> mappings. It is ignored for
        <code> groupMapping</code>.
      </p>

      <h3>Target</h3>
      <p>
        The claim/attribute name the application expects — typically a SAML attribute URI
        (e.g. <code>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress</code>)
        or an OID (<code>urn:oid:0.9.2342.19200300.100.1.3</code>), or an OIDC claim name.
      </p>

      <h3>Limits</h3>
      <p>
        The gateway does not impose its own caps on claim count or size; the relevant limits
        come from Amazon Cognito (sources) and the downstream token/assertion.
      </p>
      <table style={limitsTableStyle}>
        <thead>
          <tr>
            <th style={cellStyle}>Limit</th>
            <th style={cellStyle}>Value</th>
            <th style={cellStyle}>Enforced by</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={cellStyle}>Cognito custom attribute value length</td>
            <td style={cellStyle}>2,048 characters</td>
            <td style={cellStyle}>Amazon Cognito</td>
          </tr>
          <tr>
            <td style={cellStyle}>Cognito custom attributes per user pool</td>
            <td style={cellStyle}>50</td>
            <td style={cellStyle}>Amazon Cognito</td>
          </tr>
          <tr>
            <td style={cellStyle}>Claim mappings per application</td>
            <td style={cellStyle}>No hard limit</td>
            <td style={cellStyle}>— (gateway adds none)</td>
          </tr>
          <tr>
            <td style={cellStyle}>Target claim value size</td>
            <td style={cellStyle}>Bounded by the SAML assertion / OIDC token size</td>
            <td style={cellStyle}>Relying party / Cognito</td>
          </tr>
        </tbody>
      </table>
    </div>
  ),
};

export const roleMappingsHelp: HelpContent = {
  header: <h2>Role mappings</h2>,
  content: (
    <div>
      <p>
        Role mappings translate a user's <strong>Cognito groups</strong> into the role/value
        strings released to this application. They power claim mappings of type
        <code> groupMapping</code>: for each Cognito group the user is in, the gateway emits
        the matching <strong>Mapped value</strong> from this table.
      </p>

      <h3>Fields</h3>
      <dl>
        <dt><strong>Cognito group</strong></dt>
        <dd>
          The exact group name as it appears in the user's <code>cognito:groups</code> (case
          sensitive).
        </dd>
        <dt><strong>Mapped value</strong></dt>
        <dd>
          The value released to the application for that group — e.g. an SP role name such as
          <code> admin</code> or <code>read-only</code>.
        </dd>
      </dl>

      <h3>How it connects to claim mappings</h3>
      <p>
        Add a claim mapping with <strong>Type = groupMapping</strong> and a Target (e.g. a
        <code> roles</code> attribute). The values for that claim come from this table. A user
        in several mapped groups produces several values on the claim; groups without a
        mapping here are ignored.
      </p>

      <h3>Notes</h3>
      <ul>
        <li>Only groups present on the signed-in user's token are evaluated.</li>
        <li>Mapped values are released as plain strings (<code>xs:string</code> for SAML).</li>
        <li>The gateway imposes no cap on the number of role mappings.</li>
      </ul>
    </div>
  ),
};
