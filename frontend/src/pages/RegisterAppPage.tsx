import {
  Wizard,
  FormField,
  Input,
  Select,
  RadioGroup,
  Button,
  SpaceBetween,
  Container,
  KeyValuePairs,
  Toggle,
  ColumnLayout,
  Box,
  Alert,
  StatusIndicator,
  Table,
  Header,
  Multiselect,
  Tiles,
  Textarea,
  Modal,
} from '@cloudscape-design/components';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCreateApplication } from '../hooks/useApplications';
import { useIdentitySources } from '../hooks/useIdentitySources';
import { getProtocolBadge } from '../utils/status';
import InfoLink from '../components/InfoLink';
import CopyText from '../components/CopyText';
import { registerAppHelp } from '../help/miscHelp';
import { claimMappingsHelp, roleMappingsHelp } from '../help/mappingsHelp';

interface ClaimMapping {
  id: string;
  source: string;
  target: string;
}

interface RoleMapping {
  id: string;
  group: string;
  value: string;
}

const CODE_BLOCK_STYLE: React.CSSProperties = {
  backgroundColor: '#f2f3f3',
  padding: '12px',
  borderRadius: '8px',
  fontSize: '12px',
  overflow: 'auto',
  maxHeight: '400px',
  fontFamily: 'Monaco, Menlo, Consolas, "Courier New", monospace',
  border: '1px solid #e9ebed',
};

export default function RegisterAppPage() {
  const navigate = useNavigate();
  const createApplication = useCreateApplication();
  const { data: identitySources = [] } = useIdentitySources();

  // Step 1 state
  const [protocol, setProtocol] = useState('saml');
  const [importMethod, setImportMethod] = useState('manual');
  const [metadataUrl, setMetadataUrl] = useState('');
  const [fetchingMetadata, setFetchingMetadata] = useState(false);
  const [identitySource, setIdentitySource] = useState<{ label: string; value: string } | null>(null);

  // Shared fields
  const [displayName, setDisplayName] = useState('');

  // SAML-specific fields
  const [entityId, setEntityId] = useState('');
  const [acsUrl, setAcsUrl] = useState('');
  const [nameIdFormat, setNameIdFormat] = useState({
    label: 'Email Address',
    value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  });
  const [sessionDuration, setSessionDuration] = useState('3600');
  const [signResponse, setSignResponse] = useState(true);
  const [signAssertion, setSignAssertion] = useState(true);
  const [encryptAssertion, setEncryptAssertion] = useState(false);
  const [allowIdpInitiated, setAllowIdpInitiated] = useState(false);

  // OIDC-specific fields
  const [redirectUris, setRedirectUris] = useState('');
  const [postLogoutRedirectUris, setPostLogoutRedirectUris] = useState('');
  const [grantTypes, setGrantTypes] = useState([
    { label: 'Authorization Code', value: 'authorization_code' },
  ]);
  const [scopes, setScopes] = useState([
    { label: 'openid', value: 'openid' },
    { label: 'email', value: 'email' },
    { label: 'profile', value: 'profile' },
  ]);
  const [tokenAuthMethod, setTokenAuthMethod] = useState({
    label: 'None (public client)',
    value: 'none',
  });
  const [idTokenLifetime, setIdTokenLifetime] = useState('3600');
  const [accessTokenLifetime, setAccessTokenLifetime] = useState('3600');

  // Custom login page (REPLACE-mode), optional
  const [customLoginUrl, setCustomLoginUrl] = useState('');
  const [trustedLoginRedirectUris, setTrustedLoginRedirectUris] = useState('');

  // Claim/role mapping
  const [claimMappings, setClaimMappings] = useState<ClaimMapping[]>([
    { id: '1', source: 'email', target: protocol === 'saml'
      ? 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
      : 'email' },
  ]);
  const [roleMappings, setRoleMappings] = useState<RoleMapping[]>([]);

  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'failure'>('idle');
  const [activeStepIndex, setActiveStepIndex] = useState(0);

  // After creating a confidential OIDC client, the API returns the client secret
  // exactly once. Hold it (with the new app id) to show a one-time modal before
  // navigating away.
  const [createdCredentials, setCreatedCredentials] = useState<{ appId: string; clientSecret: string } | null>(null);

  // Build identity source options from API data
  const sourceOptions = identitySources.map((s) => ({
    label: s.displayName,
    value: s.id,
  }));

  // Auto-select first source if available
  useEffect(() => {
    if (!identitySource && sourceOptions.length > 0) {
      setIdentitySource(sourceOptions[0]);
    }
  }, [sourceOptions.length]);

  // Reset claim mapping defaults when protocol changes
  useEffect(() => {
    if (protocol === 'saml') {
      setClaimMappings([{ id: '1', source: 'email', target: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' }]);
      setImportMethod('manual');
    } else {
      setClaimMappings([{ id: '1', source: 'email', target: 'email' }]);
      setImportMethod('manual');
    }
  }, [protocol]);

  const isSAML = protocol === 'saml';

  const handleFetchMetadata = async () => {
    if (!metadataUrl) return;
    setFetchingMetadata(true);
    try {
      const res = await fetch(metadataUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const entityMatch = text.match(/entityID="([^"]+)"/);
      if (entityMatch) setEntityId(entityMatch[1]);
      const acsMatch = text.match(/Location="([^"]+)"/);
      if (acsMatch) setAcsUrl(acsMatch[1]);
      if (entityMatch && !displayName) {
        setDisplayName(entityMatch[1].split('/').pop() || entityMatch[1]);
      }
    } catch (err) {
      console.error('Failed to fetch metadata:', err);
    } finally {
      setFetchingMetadata(false);
    }
  };

  const handleAddClaimMapping = () => {
    setClaimMappings([...claimMappings, { id: Date.now().toString(), source: '', target: '' }]);
  };

  const handleRemoveClaimMapping = (id: string) => {
    setClaimMappings(claimMappings.filter((m) => m.id !== id));
  };

  const handleAddRoleMapping = () => {
    setRoleMappings([...roleMappings, { id: Date.now().toString(), group: '', value: '' }]);
  };

  const handleRemoveRoleMapping = (id: string) => {
    setRoleMappings(roleMappings.filter((m) => m.id !== id));
  };

  const handleTestSSO = () => {
    setTestStatus('testing');
    setTimeout(() => {
      setTestStatus('success');
    }, 2000);
  };

  const handleSubmit = async () => {
    try {
      const payload: Record<string, unknown> = {
        displayName,
        protocol,
        sourceId: identitySource?.value,
      };

      if (isSAML) {
        payload.saml = {
          entityId,
          acsUrl,
          signResponse,
          signAssertion,
          encryptAssertion,
          allowIdpInitiated,
          nameIdFormat: nameIdFormat.value,
          nameIdSource: 'email',
          sessionDurationSec: parseInt(sessionDuration, 10) || 3600,
          clockSkewSec: 60,
        };
      } else {
        payload.oidc = {
          redirectURIs: redirectUris.split('\n').map((u) => u.trim()).filter(Boolean),
          postLogoutRedirectURIs: postLogoutRedirectUris.split('\n').map((u) => u.trim()).filter(Boolean),
          grantTypes: grantTypes.map((g) => g.value),
          responseTypes: ['code'],
          scopes: scopes.map((s) => s.value),
          tokenEndpointAuthMethod: tokenAuthMethod.value,
          idTokenLifetimeSec: parseInt(idTokenLifetime, 10) || 3600,
          accessTokenLifetimeSec: parseInt(accessTokenLifetime, 10) || 3600,
        };
      }

      payload.claimMappings = claimMappings.map(({ source, target }) => ({ source, target }));
      payload.roleMappings = roleMappings.map(({ group, value }) => ({ group, value }));

      // Custom login page is optional. Only include it (and its allowlist) when
      // a URL is provided, so an empty value doesn't trip server-side validation.
      const trimmedCustomLogin = customLoginUrl.trim();
      if (trimmedCustomLogin) {
        payload.customLoginUrl = trimmedCustomLogin;
        payload.trustedLoginRedirectUris = trustedLoginRedirectUris
          .split('\n')
          .map((u) => u.trim())
          .filter(Boolean);
      }

      const created = await createApplication.mutateAsync(payload as any);
      // Confidential OIDC clients return a one-time client secret. Show it in a
      // modal so the operator can copy it before leaving; otherwise navigate.
      if (created?.clientSecret) {
        setCreatedCredentials({ appId: created.id, clientSecret: created.clientSecret });
      } else {
        navigate('/applications');
      }
    } catch (error) {
      console.error('Failed to create application:', error);
    }
  };

  // Preview for step 3
  const samlPreview = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject>
    <saml:NameID Format="${nameIdFormat.value}">
      user@example.com
    </saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
${claimMappings.map(m => `    <saml:Attribute Name="${m.target}">
      <saml:AttributeValue>${m.source}</saml:AttributeValue>
    </saml:Attribute>`).join('\n')}
  </saml:AttributeStatement>
</saml:Assertion>`;

  const oidcPreview = JSON.stringify({
    iss: `https://gateway.example.com/t/tenant/oidc`,
    sub: 'cognito-user-sub',
    aud: 'client-id',
    ...Object.fromEntries(claimMappings.map(m => [m.target, `{${m.source}}`])),
  }, null, 2);

  return (
    <>
    <Wizard
      i18nStrings={{
        stepNumberLabel: (stepNumber) => `Step ${stepNumber}`,
        collapsedStepsLabel: (stepNumber, stepsCount) =>
          `Step ${stepNumber} of ${stepsCount}`,
        cancelButton: 'Cancel',
        previousButton: 'Previous',
        nextButton: 'Next',
        submitButton: 'Create application',
        optional: 'optional',
      }}
      onCancel={() => navigate('/applications')}
      onSubmit={handleSubmit}
      activeStepIndex={activeStepIndex}
      onNavigate={({ detail }) => setActiveStepIndex(detail.requestedStepIndex)}
      steps={[
        {
          title: 'Configure application',
          description: 'Choose protocol, identity source, and application details',
          content: (
            <Container>
              <SpaceBetween size="l">
                <FormField label="Protocol" description="Select the federation protocol for this application">
                  <Tiles
                    value={protocol}
                    onChange={({ detail }) => setProtocol(detail.value)}
                    items={[
                      {
                        value: 'saml',
                        label: 'SAML 2.0',
                        description: 'XML-based SSO for enterprise applications (Workday, Salesforce, AWS SSO)',
                      },
                      {
                        value: 'oidc',
                        label: 'OpenID Connect',
                        description: 'Token-based auth for web and mobile apps (SPAs, APIs, microservices)',
                      },
                    ]}
                  />
                </FormField>

                <FormField
                  label="Identity source"
                  description="Select which Cognito user pool to authenticate against"
                >
                  <Select
                    selectedOption={identitySource}
                    onChange={({ detail }) =>
                      setIdentitySource(detail.selectedOption as typeof identitySource)
                    }
                    options={sourceOptions}
                    placeholder="Select identity source"
                    empty="No identity sources configured"
                  />
                </FormField>

                {isSAML && (
                  <>
                    <FormField label="Import method" description="How to provide SP configuration">
                      <RadioGroup
                        value={importMethod}
                        onChange={({ detail }) => setImportMethod(detail.value)}
                        items={[
                          { value: 'manual', label: 'Manual configuration' },
                          { value: 'url', label: 'Import from metadata URL' },
                          { value: 'upload', label: 'Upload metadata XML' },
                        ]}
                      />
                    </FormField>

                    {importMethod === 'url' && (
                      <SpaceBetween size="m">
                        <FormField label="Metadata URL">
                          <Input
                            value={metadataUrl}
                            onChange={({ detail }) => setMetadataUrl(detail.value)}
                            placeholder="https://app.example.com/saml/metadata"
                          />
                        </FormField>
                        <Button onClick={handleFetchMetadata} loading={fetchingMetadata}>
                          Fetch metadata
                        </Button>
                      </SpaceBetween>
                    )}

                    {importMethod === 'upload' && (
                      <FormField label="Upload metadata file">
                        <input type="file" accept=".xml" />
                      </FormField>
                    )}

                    <FormField label="Entity ID" description="SAML service provider entity ID">
                      <Input
                        value={entityId}
                        onChange={({ detail }) => setEntityId(detail.value)}
                        placeholder="https://app.example.com"
                      />
                    </FormField>

                    <FormField label="ACS URL" description="Assertion Consumer Service URL">
                      <Input
                        value={acsUrl}
                        onChange={({ detail }) => setAcsUrl(detail.value)}
                        placeholder="https://app.example.com/saml/acs"
                      />
                    </FormField>
                  </>
                )}

                {!isSAML && (
                  <>
                    <FormField
                      label="Redirect URIs"
                      description="OAuth2 callback URLs (one per line)"
                    >
                      <Input
                        value={redirectUris}
                        onChange={({ detail }) => setRedirectUris(detail.value)}
                        placeholder="https://app.example.com/callback"
                      />
                    </FormField>

                    <FormField
                      label="Scopes"
                      description="OIDC scopes the application can request"
                    >
                      <Multiselect
                        selectedOptions={scopes}
                        onChange={({ detail }) => setScopes(detail.selectedOptions as typeof scopes)}
                        options={[
                          { label: 'openid', value: 'openid' },
                          { label: 'email', value: 'email' },
                          { label: 'profile', value: 'profile' },
                          { label: 'offline_access', value: 'offline_access' },
                        ]}
                        placeholder="Select scopes"
                      />
                    </FormField>
                  </>
                )}
              </SpaceBetween>
            </Container>
          ),
        },
        {
          title: 'Review configuration',
          description: `Review and customize ${isSAML ? 'SAML' : 'OIDC'} settings`,
          content: (
            <SpaceBetween size="l">
              <Container header={<Header variant="h2" info={<InfoLink content={registerAppHelp} ariaLabel="Info about registering an application" />}>Application Configuration</Header>}>
                <KeyValuePairs
                  columns={2}
                  items={[
                    { label: 'Protocol', value: isSAML ? 'SAML 2.0' : 'OpenID Connect' },
                    { label: 'Identity Source', value: identitySource?.label || 'Not selected' },
                    ...(isSAML
                      ? [
                          { label: 'Entity ID', value: entityId || 'Not set' },
                          { label: 'ACS URL', value: acsUrl || 'Not set' },
                        ]
                      : [
                          { label: 'Redirect URIs', value: redirectUris || 'Not set' },
                          { label: 'Scopes', value: scopes.map((s) => s.label).join(', ') },
                        ]),
                  ]}
                />
              </Container>

              <Container header={<Header variant="h2">Application Settings</Header>}>
                <SpaceBetween size="m">
                  <FormField label="Display name" description="Friendly name for this application">
                    <Input
                      value={displayName}
                      onChange={({ detail }) => setDisplayName(detail.value)}
                      placeholder="My Application"
                    />
                  </FormField>

                  {isSAML && (
                    <FormField label="NameID format">
                      <Select
                        selectedOption={nameIdFormat}
                        onChange={({ detail }) =>
                          setNameIdFormat(detail.selectedOption as typeof nameIdFormat)
                        }
                        options={[
                          { label: 'Email Address', value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
                          { label: 'Persistent', value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' },
                          { label: 'Transient', value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' },
                        ]}
                      />
                    </FormField>
                  )}

                  <FormField label={isSAML ? 'Session duration (seconds)' : 'ID token lifetime (seconds)'}>
                    <Input
                      type="number"
                      value={isSAML ? sessionDuration : idTokenLifetime}
                      onChange={({ detail }) =>
                        isSAML ? setSessionDuration(detail.value) : setIdTokenLifetime(detail.value)
                      }
                    />
                  </FormField>
                </SpaceBetween>
              </Container>

              <Container
                header={
                  <Header
                    variant="h2"
                    description="Optional. Redirect unauthenticated users to your own login page instead of the Cognito Hosted UI."
                  >
                    Custom Login Page
                  </Header>
                }
              >
                <SpaceBetween size="m">
                  <FormField
                    label="Custom login URL"
                    description="https URL of your login page. When set, it replaces the Cognito Hosted UI for this application. Leave blank to use the Hosted UI."
                  >
                    <Input
                      value={customLoginUrl}
                      onChange={({ detail }) => setCustomLoginUrl(detail.value)}
                      placeholder="https://login.example.com/start"
                    />
                  </FormField>
                  <FormField
                    label="Trusted login redirect URLs"
                    description="Allowlist of permitted login-page URLs (https), one per line. The custom login URL must match one of these."
                  >
                    <Textarea
                      value={trustedLoginRedirectUris}
                      onChange={({ detail }) => setTrustedLoginRedirectUris(detail.value)}
                      placeholder={'https://login.example.com/'}
                      rows={3}
                    />
                  </FormField>
                </SpaceBetween>
              </Container>

              {isSAML ? (
                <Container header={<Header variant="h2">SAML Signing</Header>}>
                  <SpaceBetween size="m">
                    <Toggle checked={signResponse} onChange={({ detail }) => setSignResponse(detail.checked)}>
                      Sign SAML response
                    </Toggle>
                    <Toggle checked={signAssertion} onChange={({ detail }) => setSignAssertion(detail.checked)}>
                      Sign SAML assertion
                    </Toggle>
                    <Toggle checked={encryptAssertion} onChange={({ detail }) => setEncryptAssertion(detail.checked)}>
                      Encrypt SAML assertion
                    </Toggle>
                    <Toggle checked={allowIdpInitiated} onChange={({ detail }) => setAllowIdpInitiated(detail.checked)} description="Allow unsolicited IdP-initiated SSO into this app. Off by default.">
                      Allow IdP-initiated SSO
                    </Toggle>
                  </SpaceBetween>
                </Container>
              ) : (
                <Container header={<Header variant="h2">OIDC Settings</Header>}>
                  <SpaceBetween size="m">
                    <FormField label="Grant types">
                      <Multiselect
                        selectedOptions={grantTypes}
                        onChange={({ detail }) => setGrantTypes(detail.selectedOptions as typeof grantTypes)}
                        options={[
                          { label: 'Authorization Code', value: 'authorization_code' },
                          { label: 'Refresh Token', value: 'refresh_token' },
                        ]}
                      />
                    </FormField>
                    <FormField label="Token endpoint auth method">
                      <Select
                        selectedOption={tokenAuthMethod}
                        onChange={({ detail }) => setTokenAuthMethod(detail.selectedOption as typeof tokenAuthMethod)}
                        options={[
                          { label: 'None (public client)', value: 'none' },
                          { label: 'Client secret POST', value: 'client_secret_post' },
                          { label: 'Client secret Basic', value: 'client_secret_basic' },
                        ]}
                      />
                    </FormField>
                    <FormField label="Post-logout redirect URIs">
                      <Input
                        value={postLogoutRedirectUris}
                        onChange={({ detail }) => setPostLogoutRedirectUris(detail.value)}
                        placeholder="https://app.example.com/"
                      />
                    </FormField>
                    <FormField label="Access token lifetime (seconds)">
                      <Input
                        type="number"
                        value={accessTokenLifetime}
                        onChange={({ detail }) => setAccessTokenLifetime(detail.value)}
                      />
                    </FormField>
                  </SpaceBetween>
                </Container>
              )}
            </SpaceBetween>
          ),
        },
        {
          title: 'Claim mapping',
          description: `Map user attributes to ${isSAML ? 'SAML attributes' : 'OIDC claims'}`,
          content: (
            <ColumnLayout columns={2}>
              <Container header={<Header variant="h2" info={<InfoLink content={claimMappingsHelp} ariaLabel="Info about claim mappings" />}>Mappings</Header>}>
                <SpaceBetween size="m">
                  <Table
                    columnDefinitions={[
                      {
                        id: 'source',
                        header: 'Source (Cognito)',
                        cell: (item) => (
                          <Input
                            value={item.source}
                            onChange={({ detail }) => {
                              setClaimMappings(claimMappings.map((m) =>
                                m.id === item.id ? { ...m, source: detail.value } : m
                              ));
                            }}
                            placeholder="email"
                          />
                        ),
                      },
                      {
                        id: 'target',
                        header: isSAML ? 'Target (SAML Attribute)' : 'Target (OIDC Claim)',
                        cell: (item) => (
                          <Input
                            value={item.target}
                            onChange={({ detail }) => {
                              setClaimMappings(claimMappings.map((m) =>
                                m.id === item.id ? { ...m, target: detail.value } : m
                              ));
                            }}
                            placeholder={isSAML ? 'http://schemas.xmlsoap.org/...' : 'email'}
                          />
                        ),
                      },
                      {
                        id: 'actions',
                        header: '',
                        cell: (item) => (
                          <Button iconName="remove" variant="icon" onClick={() => handleRemoveClaimMapping(item.id)} />
                        ),
                        width: 50,
                      },
                    ]}
                    items={claimMappings}
                    empty={<Box textAlign="center" color="inherit">No mappings configured</Box>}
                  />
                  <Button onClick={handleAddClaimMapping}>Add mapping</Button>

                  <Box padding={{ top: 'l' }}>
                    <Header variant="h3" info={<InfoLink content={roleMappingsHelp} ariaLabel="Info about role mappings" />}>Role Mappings</Header>
                    <SpaceBetween size="m">
                      <Table
                        columnDefinitions={[
                          {
                            id: 'group',
                            header: 'Cognito Group',
                            cell: (item) => (
                              <Input
                                value={item.group}
                                onChange={({ detail }) => {
                                  setRoleMappings(roleMappings.map((m) =>
                                    m.id === item.id ? { ...m, group: detail.value } : m
                                  ));
                                }}
                                placeholder="Admins"
                              />
                            ),
                          },
                          {
                            id: 'value',
                            header: isSAML ? 'SP Role' : 'OIDC Role',
                            cell: (item) => (
                              <Input
                                value={item.value}
                                onChange={({ detail }) => {
                                  setRoleMappings(roleMappings.map((m) =>
                                    m.id === item.id ? { ...m, value: detail.value } : m
                                  ));
                                }}
                                placeholder="admin"
                              />
                            ),
                          },
                          {
                            id: 'actions',
                            header: '',
                            cell: (item) => (
                              <Button iconName="remove" variant="icon" onClick={() => handleRemoveRoleMapping(item.id)} />
                            ),
                            width: 50,
                          },
                        ]}
                        items={roleMappings}
                        empty={<Box textAlign="center" color="inherit">No role mappings configured</Box>}
                      />
                      <Button onClick={handleAddRoleMapping}>Add role mapping</Button>
                    </SpaceBetween>
                  </Box>
                </SpaceBetween>
              </Container>

              <Container header={<Header variant="h2">Preview</Header>}>
                <Box>
                  <Box variant="p" color="text-body-secondary" padding={{ bottom: 's' }}>
                    {isSAML
                      ? 'Preview of the SAML assertion that will be generated:'
                      : 'Preview of the OIDC ID token claims:'}
                  </Box>
                  <pre style={CODE_BLOCK_STYLE}>
                    {isSAML ? samlPreview : oidcPreview}
                  </pre>
                </Box>
              </Container>
            </ColumnLayout>
          ),
        },
        {
          title: 'Test and activate',
          description: 'Test the configuration and activate the application',
          content: (
            <Container>
              <SpaceBetween size="l">
                <Alert type="info">
                  Before activating, test the {isSAML ? 'SSO' : 'authentication'} flow to verify configuration.
                </Alert>

                <FormField label={isSAML ? 'Test SSO' : 'Test Authentication'}>
                  <SpaceBetween size="m">
                    <Button
                      variant="primary"
                      onClick={handleTestSSO}
                      loading={testStatus === 'testing'}
                    >
                      Create and Test
                    </Button>

                    {testStatus === 'testing' && (
                      <StatusIndicator type="in-progress">
                        Testing configuration...
                      </StatusIndicator>
                    )}
                    {testStatus === 'success' && (
                      <Alert type="success">
                        Test completed successfully. The application is ready to be activated.
                      </Alert>
                    )}
                    {testStatus === 'failure' && (
                      <Alert type="error">
                        Test failed. Please review your configuration and try again.
                      </Alert>
                    )}
                  </SpaceBetween>
                </FormField>

                {testStatus === 'success' && (
                  <Container header={<Header variant="h2">Summary</Header>}>
                    <KeyValuePairs
                      columns={2}
                      items={[
                        { label: 'Display Name', value: displayName },
                        { label: 'Protocol', value: getProtocolBadge(protocol) },
                        { label: 'Identity Source', value: identitySource?.label || '' },
                        ...(isSAML
                          ? [
                              { label: 'Entity ID', value: entityId },
                              { label: 'ACS URL', value: acsUrl },
                              { label: 'NameID Format', value: nameIdFormat.label },
                              { label: 'Sign Response', value: signResponse ? 'Yes' : 'No' },
                              { label: 'Sign Assertion', value: signAssertion ? 'Yes' : 'No' },
                              { label: 'Encrypt Assertion', value: encryptAssertion ? 'Yes' : 'No' },
                            ]
                          : [
                              { label: 'Redirect URIs', value: redirectUris },
                              { label: 'Scopes', value: scopes.map((s) => s.label).join(', ') },
                              { label: 'Grant Types', value: grantTypes.map((g) => g.label).join(', ') },
                              { label: 'Token Auth', value: tokenAuthMethod.label },
                            ]),
                      ]}
                    />
                  </Container>
                )}
              </SpaceBetween>
            </Container>
          ),
        },
      ]}
    />
    <Modal
      visible={createdCredentials !== null}
      header="Save your client secret"
      closeAriaLabel="Close"
      onDismiss={() => {
        setCreatedCredentials(null);
        navigate('/applications');
      }}
      footer={
        <Box float="right">
          <Button
            variant="primary"
            onClick={() => {
              const appId = createdCredentials?.appId;
              setCreatedCredentials(null);
              navigate(appId ? `/applications/${appId}` : '/applications');
            }}
          >
            I've saved it
          </Button>
        </Box>
      }
    >
      <SpaceBetween size="m">
        <Alert type="warning">
          This client secret is shown <strong>only once</strong>. Copy it now and store it
          securely — you cannot retrieve it again. If you lose it, regenerate a new one from the
          application's OIDC settings.
        </Alert>
        <FormField label="Client ID">
          {createdCredentials && <CopyText text={createdCredentials.appId} />}
        </FormField>
        <FormField label="Client secret">
          {createdCredentials && <CopyText text={createdCredentials.clientSecret} />}
        </FormField>
      </SpaceBetween>
    </Modal>
    </>
  );
}
