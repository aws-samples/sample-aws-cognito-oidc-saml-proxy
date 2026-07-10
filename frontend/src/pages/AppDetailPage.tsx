import { authFetch } from '../auth';
import {
  SpaceBetween,
  Header,
  Container,
  Tabs,
  KeyValuePairs,
  Table,
  Button,
  Box,
  Alert,
  Toggle,
  FormField,
  Input,
  Select,
  Textarea,
  TextFilter,
  Spinner,
  Multiselect,
  MultiselectProps,
} from '@cloudscape-design/components';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { useParams, useNavigate } from 'react-router-dom';
import { useApplication, useUpdateApplication } from '../hooks/useApplications';
import { useIntegration } from '../hooks/useIntegration';
import { useState, useEffect } from 'react';
import PageLayout from '../components/PageLayout';
import CopyText from '../components/CopyText';
import InfoLink from '../components/InfoLink';
import { claimMappingsHelp, roleMappingsHelp } from '../help/mappingsHelp';
import { appOverviewHelp, samlConfigHelp, oidcConfigHelp, customLoginHelp, integrationHelp } from '../help/appDetailHelp';
import { getStatusIndicator, getProtocolBadge } from '../utils/status';
import { formatDateTime } from '../utils/format';

function CodeBlock({ children }: { children: string }) {
  return (
    <pre style={{ backgroundColor: '#1a1a2e', color: '#e0e0e0', padding: '1rem', borderRadius: '8px', overflow: 'auto', fontSize: '0.8125rem', lineHeight: '1.5' }}>
      {children}
    </pre>
  );
}

interface ClaimMappingRow {
  id: string;
  source: string;
  target: string;
  type: 'cognito' | 'static' | 'groupMapping';
  required: boolean;
  defaultValue?: string;
}

interface RoleMappingRow {
  id: string;
  cognitoGroup: string;
  mappedValue: string;
}

export default function AppDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: application, isLoading, isError, error } = useApplication(id!);
  const { data: integration } = useIntegration(id!);
  const updateApplication = useUpdateApplication();

  const [secretRotateStatus, setSecretRotateStatus] = useState<'idle' | 'rotating' | 'success'>('idle');
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);
  const [previewStatus, setPreviewStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [previewXml, setPreviewXml] = useState<string>('');

  // Protocol tab state (SAML)
  const [samlEntityId, setSamlEntityId] = useState('');
  const [samlAcsUrl, setSamlAcsUrl] = useState('');
  const [samlNameIdFormat, setSamlNameIdFormat] = useState<{ label: string; value: string } | null>(null);
  const [samlNameIdSource, setSamlNameIdSource] = useState('');
  const [samlSignResponse, setSamlSignResponse] = useState(false);
  const [samlSignAssertion, setSamlSignAssertion] = useState(false);
  const [samlEncryptAssertion, setSamlEncryptAssertion] = useState(false);
  const [samlAllowIdpInitiated, setSamlAllowIdpInitiated] = useState(false);
  const [samlSloUrl, setSamlSloUrl] = useState('');
  const [samlSessionDuration, setSamlSessionDuration] = useState('');
  const [samlClockSkew, setSamlClockSkew] = useState('');

  // Protocol tab state (OIDC)
  const [oidcRedirectUris, setOidcRedirectUris] = useState('');
  const [oidcPostLogoutUris, setOidcPostLogoutUris] = useState('');
  const [oidcGrantTypes, setOidcGrantTypes] = useState<ReadonlyArray<MultiselectProps.Option>>([]);
  const [oidcResponseTypes, setOidcResponseTypes] = useState<ReadonlyArray<MultiselectProps.Option>>([]);
  const [oidcScopes, setOidcScopes] = useState<ReadonlyArray<MultiselectProps.Option>>([]);
  const [oidcTokenAuthMethod, setOidcTokenAuthMethod] = useState<{ label: string; value: string } | null>(null);
  const [oidcIdTokenLifetime, setOidcIdTokenLifetime] = useState('');
  const [oidcAccessTokenLifetime, setOidcAccessTokenLifetime] = useState('');

  // Mappings tab state
  const [claimMappings, setClaimMappings] = useState<ClaimMappingRow[]>([]);
  const [roleMappings, setRoleMappings] = useState<RoleMappingRow[]>([]);

  // Custom login page (REPLACE-mode) config
  const [customLoginUrl, setCustomLoginUrl] = useState('');
  const [trustedLoginRedirectUris, setTrustedLoginRedirectUris] = useState('');
  const [loginSaveError, setLoginSaveError] = useState<string | null>(null);
  const [loginSaveStatus, setLoginSaveStatus] = useState<'idle' | 'saving' | 'success'>('idle');

  // Collection hooks for mapping tables
  const {
    items: claimItems,
    collectionProps: claimCollectionProps,
    filterProps: claimFilterProps,
  } = useCollection(claimMappings, {
    filtering: {
      empty: (
        <Box textAlign="center" color="inherit">
          <b>No claim mappings</b>
        </Box>
      ),
      noMatch: (
        <Box textAlign="center" color="inherit">
          <b>No matches</b>
        </Box>
      ),
    },
    sorting: {},
  });

  const {
    items: roleItems,
    collectionProps: roleCollectionProps,
    filterProps: roleFilterProps,
  } = useCollection(roleMappings, {
    filtering: {
      empty: (
        <Box textAlign="center" color="inherit">
          <b>No role mappings</b>
        </Box>
      ),
      noMatch: (
        <Box textAlign="center" color="inherit">
          <b>No matches</b>
        </Box>
      ),
    },
    sorting: {},
  });

  // Pre-populate SAML form fields from API data
  // NOTE: hooks must be called before any early returns (React rules of hooks)
  useEffect(() => {
    if (application?.saml) {
      setSamlEntityId(application.saml.entityId || '');
      setSamlAcsUrl(application.saml.acsUrl || '');
      setSamlNameIdSource(application.saml.nameIdSource || 'email');
      setSamlSignResponse(application.saml.signResponse ?? false);
      setSamlSignAssertion(application.saml.signAssertion ?? false);
      setSamlEncryptAssertion(application.saml.encryptAssertion ?? false);
      setSamlAllowIdpInitiated(application.saml.allowIdpInitiated ?? false);
      setSamlSloUrl(application.saml.sloUrl || '');
      setSamlSessionDuration(String(application.saml.sessionDurationSec ?? 3600));
      setSamlClockSkew(String(application.saml.clockSkewSec ?? 60));
      const fmt = application.saml.nameIdFormat;
      if (fmt) {
        const labelMap: Record<string, string> = {
          'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress': 'Email Address',
          'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent': 'Persistent',
          'urn:oasis:names:tc:SAML:2.0:nameid-format:transient': 'Transient',
        };
        setSamlNameIdFormat({ label: labelMap[fmt] || fmt, value: fmt });
      }
    }
  }, [application?.saml]);

  // Pre-populate custom login config from API data
  useEffect(() => {
    setCustomLoginUrl(application?.customLoginUrl || '');
    setTrustedLoginRedirectUris((application?.trustedLoginRedirectUris || []).join('\n'));
  }, [application?.customLoginUrl, application?.trustedLoginRedirectUris]);

  // Pre-populate OIDC form fields from API data
  useEffect(() => {
    if (application?.oidc) {
      setOidcRedirectUris((application.oidc.redirectURIs || []).join('\n'));
      setOidcPostLogoutUris((application.oidc.postLogoutRedirectURIs || []).join('\n'));
      setOidcGrantTypes((application.oidc.grantTypes || []).map(g => {
        const labelMap: Record<string, string> = {
          authorization_code: 'Authorization Code',
          refresh_token: 'Refresh Token',
          client_credentials: 'Client Credentials',
        };
        return { label: labelMap[g] || g, value: g };
      }));
      setOidcResponseTypes((application.oidc.responseTypes || []).map(r => ({ label: r, value: r })));
      setOidcScopes((application.oidc.scopes || []).map(s => ({ label: s, value: s })));
      setOidcIdTokenLifetime(String(application.oidc.idTokenLifetimeSec ?? 3600));
      setOidcAccessTokenLifetime(String(application.oidc.accessTokenLifetimeSec ?? 3600));
      const method = application.oidc.tokenEndpointAuthMethod;
      if (method) {
        const authLabelMap: Record<string, string> = {
          none: 'None (public client)',
          client_secret_post: 'Client secret POST',
          client_secret_basic: 'Client secret Basic',
        };
        setOidcTokenAuthMethod({ label: authLabelMap[method] || method, value: method });
      }
    }
  }, [application?.oidc]);

  // Load claim and role mappings from API
  useEffect(() => {
    if (!id) return;
    authFetch(`/api/v1/applications/${id}/claim-mappings`)
      .then(res => res.ok ? res.json() : [])
      .then((data: Array<{ name: string; sourceType: string; sourceAttribute: string; targetAttribute: string; required: boolean; defaultValue?: string }>) => {
        if (Array.isArray(data) && data.length > 0) {
          setClaimMappings(data.map((m, i) => ({
            id: String(i),
            source: m.sourceAttribute,
            target: m.targetAttribute,
            type: m.sourceType as ClaimMappingRow['type'],
            required: m.required,
            defaultValue: m.defaultValue || '',
          })));
        }
      })
      .catch(() => {});
    authFetch(`/api/v1/applications/${id}/role-mappings`)
      .then(res => res.ok ? res.json() : [])
      .then((data: Array<{ cognitoGroup: string; mappedValue: string }>) => {
        if (Array.isArray(data) && data.length > 0) {
          setRoleMappings(data.map((m, i) => ({
            id: String(i),
            cognitoGroup: m.cognitoGroup,
            mappedValue: m.mappedValue,
          })));
        }
      })
      .catch(() => {});
  }, [id]);

  if (isLoading) {
    return (
      <PageLayout title="Application">
        <Box textAlign="center" padding="l">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (isError) {
    return (
      <PageLayout title="Application">
        <Alert type="error" header="Unable to load application">
          {error instanceof Error ? error.message : 'An unexpected error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  if (!application) {
    return (
      <PageLayout title="Application">
        <Alert type="error">Application not found</Alert>
      </PageLayout>
    );
  }

  const isSAML = application.protocol?.toLowerCase() === 'saml';

  const handleSaveProtocol = async () => {
    try {
      if (isSAML) {
        await updateApplication.mutateAsync({
          id: id!,
          data: {
            saml: {
              entityId: samlEntityId || application.saml?.entityId || '',
              acsUrl: samlAcsUrl || application.saml?.acsUrl || '',
              nameIdFormat: samlNameIdFormat?.value || application.saml?.nameIdFormat || '',
              nameIdSource: samlNameIdSource || application.saml?.nameIdSource || 'email',
              signResponse: samlSignResponse,
              signAssertion: samlSignAssertion,
              encryptAssertion: samlEncryptAssertion,
              allowIdpInitiated: samlAllowIdpInitiated,
              sloUrl: samlSloUrl || application.saml?.sloUrl || '',
              sessionDurationSec: parseInt(samlSessionDuration, 10) || application.saml?.sessionDurationSec || 3600,
              clockSkewSec: parseInt(samlClockSkew, 10) || application.saml?.clockSkewSec || 60,
            },
          },
        });
      } else {
        const updated = await updateApplication.mutateAsync({
          id: id!,
          data: {
            oidc: {
              redirectURIs: oidcRedirectUris.split('\n').map((u) => u.trim()).filter(Boolean),
              postLogoutRedirectURIs: oidcPostLogoutUris.split('\n').map((u) => u.trim()).filter(Boolean),
              grantTypes: oidcGrantTypes.map(g => g.value || '').filter(Boolean),
              responseTypes: oidcResponseTypes.map(r => r.value || '').filter(Boolean),
              scopes: oidcScopes.map(s => s.value || '').filter(Boolean),
              tokenEndpointAuthMethod: oidcTokenAuthMethod?.value || 'none',
              idTokenLifetimeSec: parseInt(oidcIdTokenLifetime, 10) || 3600,
              accessTokenLifetimeSec: parseInt(oidcAccessTokenLifetime, 10) || 3600,
            },
          },
        });
        // If the save just minted a confidential client secret (e.g. switching
        // to client_secret_basic/post for the first time), surface it once.
        if (updated?.clientSecret) {
          setRotatedSecret(updated.clientSecret);
          setSecretRotateStatus('success');
        }
      }
    } catch (err) {
      console.error('Failed to save protocol settings:', err);
    }
  };

  const handleSaveLogin = async () => {
    setLoginSaveStatus('saving');
    setLoginSaveError(null);
    const uris = trustedLoginRedirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean);
    try {
      await updateApplication.mutateAsync({
        id: id!,
        data: {
          // Include displayName + sourceId so the partial update does not clear them.
          displayName: application.displayName,
          sourceId: application.sourceId,
          customLoginUrl: customLoginUrl.trim(),
          trustedLoginRedirectUris: uris,
        },
      });
      setLoginSaveStatus('success');
    } catch (err) {
      setLoginSaveStatus('idle');
      setLoginSaveError(err instanceof Error ? err.message : 'Failed to save login settings');
    }
  };

  const handleRotateSecret = async () => {
    setSecretRotateStatus('rotating');
    try {
      const res = await authFetch(`/api/v1/applications/${id}/rotate-secret`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setRotatedSecret(data.clientSecret);
        setSecretRotateStatus('success');
      }
    } catch (err) {
      console.error('Failed to rotate secret:', err);
      setSecretRotateStatus('idle');
    }
  };

  const handleSaveClaimMappings = async () => {
    try {
      await authFetch(`/api/v1/applications/${id}/claim-mappings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mappings: claimMappings.map((m) => ({
            name: m.target,
            sourceType: m.type,
            sourceAttribute: m.source,
            targetAttribute: m.target,
            required: m.required,
            defaultValue: m.defaultValue,
          })),
        }),
      });
    } catch (err) {
      console.error('Failed to save claim mappings:', err);
    }
  };

  const handleSaveRoleMappings = async () => {
    try {
      await authFetch(`/api/v1/applications/${id}/role-mappings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mappings: roleMappings.map((m) => ({
            cognitoGroup: m.cognitoGroup,
            mappedValue: m.mappedValue,
          })),
        }),
      });
    } catch (err) {
      console.error('Failed to save role mappings:', err);
    }
  };

  const handleAddClaimMapping = () => {
    setClaimMappings([
      ...claimMappings,
      {
        id: Date.now().toString(),
        source: '',
        target: '',
        type: 'cognito',
        required: false,
        defaultValue: '',
      },
    ]);
  };

  const handleRemoveClaimMapping = (rowId: string) => {
    setClaimMappings(claimMappings.filter((m) => m.id !== rowId));
  };

  const handleAddRoleMapping = () => {
    setRoleMappings([
      ...roleMappings,
      {
        id: Date.now().toString(),
        cognitoGroup: '',
        mappedValue: '',
      },
    ]);
  };

  const handleRemoveRoleMapping = (rowId: string) => {
    setRoleMappings(roleMappings.filter((m) => m.id !== rowId));
  };

  const handleTestSSO = () => {
    const ssoUrl = isSAML
      ? integration?.saml?.ssoUrl
      : integration?.oidc?.authorizationUrl;
    if (ssoUrl) {
      window.open(ssoUrl, '_blank');
    }
  };

  const handlePreviewAssertion = async () => {
    setPreviewStatus('loading');
    try {
      const res = await authFetch(`/api/v1/applications/${id}/claim-mappings/preview`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setPreviewXml(data.xml || data.decodedXml || '');
        setPreviewStatus('success');
      } else {
        setPreviewStatus('error');
      }
    } catch (err) {
      console.error('Failed to preview assertion:', err);
      setPreviewStatus('error');
    }
  };

  const handleToggleStatus = async () => {
    try {
      await updateApplication.mutateAsync({
        id: id!,
        data: { displayName: application.displayName },
      });
    } catch (err) {
      console.error('Failed to toggle status:', err);
    }
  };

  const handleDelete = async () => {
    if (confirm(`Delete application "${application.displayName}"?`)) {
      try {
        await authFetch(`/api/v1/applications/${id}`, { method: 'DELETE' });
        navigate('/applications');
      } catch (err) {
        console.error('Failed to delete application:', err);
      }
    }
  };

  return (
    <PageLayout
      title={application.displayName}
      description={getStatusIndicator(application.status)}
      actions={
        <SpaceBetween direction="horizontal" size="xs">
          <Button onClick={() => navigate(`/applications/${id}/edit`)}>
            Edit
          </Button>
          <Button
            onClick={handleToggleStatus}
            loading={updateApplication.isPending}
          >
            {application.status === 'active' ? 'Disable' : 'Enable'}
          </Button>
          <Button onClick={handleDelete}>Delete</Button>
        </SpaceBetween>
      }
    >
      <Tabs
        tabs={[
          {
            label: 'Overview',
            id: 'overview',
            content: (
              <Container header={<Header variant="h2" info={<InfoLink content={appOverviewHelp} ariaLabel="Info about this application" />}>Details</Header>}>
                <KeyValuePairs
                  columns={2}
                  items={[
                    {
                      label: 'Application ID',
                      value: <CopyText text={application.id} />,
                    },
                    {
                      label: 'Display Name',
                      value: application.displayName,
                    },
                    {
                      label: 'Protocol',
                      value: getProtocolBadge(application.protocol),
                    },
                    {
                      label: 'Status',
                      value: getStatusIndicator(application.status),
                    },
                    {
                      label: 'Identity Source',
                      value: application.sourceId ? (
                        <CopyText text={application.sourceId} />
                      ) : 'Not assigned',
                    },
                    {
                      label: 'Created',
                      value: formatDateTime(application.createdAt),
                    },
                    {
                      label: 'Updated',
                      value: formatDateTime(application.updatedAt),
                    },
                  ]}
                />
              </Container>
            ),
          },
          {
            label: 'Protocol',
            id: 'protocol',
            content: isSAML ? (
              <Container header={<Header variant="h2" info={<InfoLink content={samlConfigHelp} ariaLabel="Info about SAML configuration" />}>SAML Configuration</Header>}>
                <SpaceBetween size="l">
                  <FormField label="Entity ID">
                    <Input
                      value={samlEntityId}
                      onChange={({ detail }) => setSamlEntityId(detail.value)}
                      placeholder="https://app.example.com"
                    />
                  </FormField>
                  <FormField label="ACS URL">
                    <Input
                      value={samlAcsUrl}
                      onChange={({ detail }) => setSamlAcsUrl(detail.value)}
                      placeholder="https://app.example.com/saml/acs"
                    />
                  </FormField>
                  <FormField label="NameID Format">
                    <Select
                      selectedOption={
                        samlNameIdFormat || {
                          label: 'Email Address',
                          value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                        }
                      }
                      onChange={({ detail }) =>
                        setSamlNameIdFormat(detail.selectedOption as typeof samlNameIdFormat)
                      }
                      options={[
                        {
                          label: 'Email Address',
                          value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                        },
                        {
                          label: 'Persistent',
                          value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                        },
                        {
                          label: 'Transient',
                          value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                        },
                      ]}
                    />
                  </FormField>
                  <FormField label="NameID Source">
                    <Input
                      value={samlNameIdSource}
                      onChange={({ detail }) => setSamlNameIdSource(detail.value)}
                      placeholder="email"
                    />
                  </FormField>
                  <Toggle
                    checked={samlSignResponse}
                    onChange={({ detail }) => setSamlSignResponse(detail.checked)}
                  >
                    Sign Response
                  </Toggle>
                  <Toggle
                    checked={samlSignAssertion}
                    onChange={({ detail }) => setSamlSignAssertion(detail.checked)}
                  >
                    Sign Assertion
                  </Toggle>
                  <Toggle
                    checked={samlEncryptAssertion}
                    onChange={({ detail }) => setSamlEncryptAssertion(detail.checked)}
                  >
                    Encrypt Assertion
                  </Toggle>
                  <Toggle
                    checked={samlAllowIdpInitiated}
                    onChange={({ detail }) => setSamlAllowIdpInitiated(detail.checked)}
                    description="Allow unsolicited (IdP-initiated) SSO into this app via the gateway's /saml/idp-initiate endpoint. Off by default — IdP-initiated SSO is an opt-in because it can be an abuse vector."
                  >
                    Allow IdP-initiated SSO
                  </Toggle>
                  <FormField label="SLO URL" description="Single Logout URL (optional)">
                    <Input
                      value={samlSloUrl}
                      onChange={({ detail }) => setSamlSloUrl(detail.value)}
                      placeholder="https://app.example.com/saml/slo"
                    />
                  </FormField>
                  <FormField label="Session Duration (seconds)">
                    <Input
                      type="number"
                      value={samlSessionDuration}
                      onChange={({ detail }) => setSamlSessionDuration(detail.value)}
                    />
                  </FormField>
                  <FormField label="Clock Skew (seconds)">
                    <Input
                      type="number"
                      value={samlClockSkew}
                      onChange={({ detail }) => setSamlClockSkew(detail.value)}
                    />
                  </FormField>
                  <Button variant="primary" onClick={handleSaveProtocol}>
                    Save
                  </Button>
                </SpaceBetween>
              </Container>
            ) : (
              <Container header={<Header variant="h2" info={<InfoLink content={oidcConfigHelp} ariaLabel="Info about OIDC configuration" />}>OIDC Configuration</Header>}>
                <SpaceBetween size="l">
                  <FormField
                    label="Client ID"
                    description="The relying party authenticates with this client ID. For a confidential client (e.g. an Amazon Cognito user pool as the relying party), pair it with the client secret below."
                  >
                    <CopyText text={application.id} />
                  </FormField>
                  <FormField label="Redirect URIs" description="One per line">
                    <Textarea
                      value={oidcRedirectUris}
                      onChange={({ detail }) => setOidcRedirectUris(detail.value)}
                      placeholder="https://app.example.com/callback"
                      rows={3}
                    />
                  </FormField>
                  <FormField label="Post-Logout Redirect URIs" description="One per line">
                    <Textarea
                      value={oidcPostLogoutUris}
                      onChange={({ detail }) => setOidcPostLogoutUris(detail.value)}
                      placeholder="https://app.example.com/"
                      rows={3}
                    />
                  </FormField>
                  <FormField label="Grant Types" description="OAuth 2.0 grant types the application supports">
                    <Multiselect
                      selectedOptions={oidcGrantTypes}
                      onChange={({ detail }) => setOidcGrantTypes(detail.selectedOptions)}
                      options={[
                        { label: 'Authorization Code', value: 'authorization_code' },
                        { label: 'Refresh Token', value: 'refresh_token' },
                        { label: 'Client Credentials', value: 'client_credentials' },
                      ]}
                      placeholder="Select grant types"
                    />
                  </FormField>
                  <FormField label="Response Types" description="OAuth 2.0 response types the application supports">
                    <Multiselect
                      selectedOptions={oidcResponseTypes}
                      onChange={({ detail }) => setOidcResponseTypes(detail.selectedOptions)}
                      options={[
                        { label: 'code', value: 'code' },
                        { label: 'id_token', value: 'id_token' },
                        { label: 'id_token token', value: 'id_token token' },
                      ]}
                      placeholder="Select response types"
                    />
                  </FormField>
                  <FormField label="Scopes" description="OAuth 2.0 scopes the application can request">
                    <Multiselect
                      selectedOptions={oidcScopes}
                      onChange={({ detail }) => setOidcScopes(detail.selectedOptions)}
                      options={[
                        { label: 'openid', value: 'openid' },
                        { label: 'email', value: 'email' },
                        { label: 'profile', value: 'profile' },
                        { label: 'offline_access', value: 'offline_access' },
                      ]}
                      placeholder="Select scopes"
                    />
                  </FormField>
                  <FormField label="Token Endpoint Auth Method">
                    <Select
                      selectedOption={
                        oidcTokenAuthMethod || {
                          label: 'None (public client)',
                          value: 'none',
                        }
                      }
                      onChange={({ detail }) =>
                        setOidcTokenAuthMethod(detail.selectedOption as typeof oidcTokenAuthMethod)
                      }
                      options={[
                        { label: 'None (public client)', value: 'none' },
                        { label: 'Client secret POST', value: 'client_secret_post' },
                        { label: 'Client secret Basic', value: 'client_secret_basic' },
                      ]}
                    />
                  </FormField>
                  <FormField label="ID Token Lifetime (seconds)">
                    <Input
                      type="number"
                      value={oidcIdTokenLifetime}
                      onChange={({ detail }) => setOidcIdTokenLifetime(detail.value)}
                      placeholder="3600"
                    />
                  </FormField>
                  <FormField label="Access Token Lifetime (seconds)">
                    <Input
                      type="number"
                      value={oidcAccessTokenLifetime}
                      onChange={({ detail }) => setOidcAccessTokenLifetime(detail.value)}
                      placeholder="3600"
                    />
                  </FormField>
                  {oidcTokenAuthMethod?.value !== 'none' && (
                    <SpaceBetween size="m">
                      <Alert type="info">
                        This is a <strong>confidential client</strong>. It authenticates to the
                        token endpoint with a client secret. A secret is generated automatically
                        when you first save with a client-secret method; use{' '}
                        <strong>Regenerate Secret</strong> to roll it. A secret is shown only once
                        when created or regenerated, so copy it immediately. To configure an
                        Amazon Cognito user pool as the relying party, use the Client ID above with
                        this secret and pick the auth method Cognito expects (Cognito uses
                        client secret authentication for its OIDC identity providers).
                      </Alert>
                      <Button
                        onClick={handleRotateSecret}
                        loading={secretRotateStatus === 'rotating'}
                      >
                        Regenerate Secret
                      </Button>
                      {secretRotateStatus === 'success' && rotatedSecret && (
                        <Alert
                          type="success"
                          dismissible
                          onDismiss={() => {
                            setRotatedSecret(null);
                            setSecretRotateStatus('idle');
                          }}
                          header="Client secret (shown once)"
                        >
                          <SpaceBetween size="xs">
                            <span>Copy this now. You will not be able to view it again.</span>
                            <CopyText text={rotatedSecret} />
                          </SpaceBetween>
                        </Alert>
                      )}
                    </SpaceBetween>
                  )}
                  <Button variant="primary" onClick={handleSaveProtocol}>
                    Save
                  </Button>
                </SpaceBetween>
              </Container>
            ),
          },
          {
            label: 'Custom login',
            id: 'custom-login',
            content: (
              <Container
                header={
                  <Header
                    variant="h2"
                    info={<InfoLink content={customLoginHelp} ariaLabel="Info about the custom login page" />}
                    description="Redirect unauthenticated users to your own login page instead of the Cognito Hosted UI."
                  >
                    Custom Login Page
                  </Header>
                }
              >
                <SpaceBetween size="m">
                  <Alert type="info">
                    When a custom login URL is set, it <strong>replaces</strong> the
                    Cognito Hosted UI for this application: unauthenticated users are
                    redirected there. Your page authenticates the user and posts the
                    Cognito ID token back to the gateway's session-establish endpoint
                    (<code>/t/&lt;tenant&gt;/{isSAML ? 'saml' : 'oidc'}/login/complete</code>)
                    to resume SSO. Leave the URL blank to use the Cognito Hosted UI.
                  </Alert>

                  {loginSaveError && (
                    <Alert type="error" dismissible onDismiss={() => setLoginSaveError(null)}>
                      {loginSaveError}
                    </Alert>
                  )}
                  {loginSaveStatus === 'success' && (
                    <Alert type="success" dismissible onDismiss={() => setLoginSaveStatus('idle')}>
                      Custom login settings saved.
                    </Alert>
                  )}

                  <FormField
                    label="Custom login URL"
                    description="https URL of your login page. Must be covered by the trusted redirect allowlist below."
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
                      rows={4}
                    />
                  </FormField>

                  <Button
                    variant="primary"
                    onClick={handleSaveLogin}
                    loading={loginSaveStatus === 'saving'}
                  >
                    Save
                  </Button>
                </SpaceBetween>
              </Container>
            ),
          },
          {
            label: 'Mappings',
            id: 'mappings',
            content: (
              <SpaceBetween size="l">
                <Container header={<Header variant="h2" info={<InfoLink content={claimMappingsHelp} ariaLabel="Info about claim mappings" />}>Claim Mappings</Header>}>
                  <SpaceBetween size="m">
                    <Table
                      {...claimCollectionProps}
                      columnDefinitions={[
                        {
                          id: 'source',
                          header: 'Source',
                          cell: (item) => (
                            <Input
                              value={item.source}
                              onChange={({ detail }) =>
                                setClaimMappings(
                                  claimMappings.map((m) =>
                                    m.id === item.id ? { ...m, source: detail.value } : m
                                  )
                                )
                              }
                              placeholder="email"
                            />
                          ),
                        },
                        {
                          id: 'target',
                          header: 'Target',
                          cell: (item) => (
                            <Input
                              value={item.target}
                              onChange={({ detail }) =>
                                setClaimMappings(
                                  claimMappings.map((m) =>
                                    m.id === item.id ? { ...m, target: detail.value } : m
                                  )
                                )
                              }
                              placeholder="email"
                            />
                          ),
                        },
                        {
                          id: 'type',
                          header: 'Type',
                          cell: (item) => (
                            <Select
                              expandToViewport
                              selectedOption={{ label: item.type, value: item.type }}
                              onChange={({ detail }) =>
                                setClaimMappings(
                                  claimMappings.map((m) =>
                                    m.id === item.id
                                      ? { ...m, type: detail.selectedOption.value as typeof item.type }
                                      : m
                                  )
                                )
                              }
                              options={[
                                { label: 'cognito', value: 'cognito' },
                                { label: 'static', value: 'static' },
                                { label: 'groupMapping', value: 'groupMapping' },
                              ]}
                            />
                          ),
                        },
                        {
                          id: 'required',
                          header: 'Required',
                          cell: (item) => (
                            <Toggle
                              checked={item.required}
                              onChange={({ detail }) =>
                                setClaimMappings(
                                  claimMappings.map((m) =>
                                    m.id === item.id ? { ...m, required: detail.checked } : m
                                  )
                                )
                              }
                            />
                          ),
                        },
                        {
                          id: 'default',
                          header: 'Default Value',
                          cell: (item) => (
                            <Input
                              value={item.defaultValue || ''}
                              onChange={({ detail }) =>
                                setClaimMappings(
                                  claimMappings.map((m) =>
                                    m.id === item.id ? { ...m, defaultValue: detail.value } : m
                                  )
                                )
                              }
                            />
                          ),
                        },
                        {
                          id: 'actions',
                          header: '',
                          cell: (item) => (
                            <Button
                              iconName="remove"
                              variant="icon"
                              onClick={() => handleRemoveClaimMapping(item.id)}
                            />
                          ),
                        },
                      ]}
                      items={claimItems}
                      filter={
                        <TextFilter
                          {...claimFilterProps}
                          filteringPlaceholder="Find claim mappings"
                          filteringAriaLabel="Filter claim mappings"
                        />
                      }
                      empty={
                        <Box textAlign="center" color="inherit">
                          <b>No claim mappings</b>
                        </Box>
                      }
                    />
                    <SpaceBetween direction="horizontal" size="xs">
                      <Button onClick={handleAddClaimMapping}>Add mapping</Button>
                      <Button variant="primary" onClick={handleSaveClaimMappings}>
                        Save
                      </Button>
                    </SpaceBetween>
                  </SpaceBetween>
                </Container>

                <Container header={<Header variant="h2" info={<InfoLink content={roleMappingsHelp} ariaLabel="Info about role mappings" />}>Role Mappings</Header>}>
                  <SpaceBetween size="m">
                    <Table
                      {...roleCollectionProps}
                      columnDefinitions={[
                        {
                          id: 'group',
                          header: 'Cognito Group',
                          cell: (item) => (
                            <Input
                              value={item.cognitoGroup}
                              onChange={({ detail }) =>
                                setRoleMappings(
                                  roleMappings.map((m) =>
                                    m.id === item.id ? { ...m, cognitoGroup: detail.value } : m
                                  )
                                )
                              }
                              placeholder="Admins"
                            />
                          ),
                        },
                        {
                          id: 'value',
                          header: 'Mapped Value',
                          cell: (item) => (
                            <Input
                              value={item.mappedValue}
                              onChange={({ detail }) =>
                                setRoleMappings(
                                  roleMappings.map((m) =>
                                    m.id === item.id ? { ...m, mappedValue: detail.value } : m
                                  )
                                )
                              }
                              placeholder="admin"
                            />
                          ),
                        },
                        {
                          id: 'actions',
                          header: '',
                          cell: (item) => (
                            <Button
                              iconName="remove"
                              variant="icon"
                              onClick={() => handleRemoveRoleMapping(item.id)}
                            />
                          ),
                        },
                      ]}
                      items={roleItems}
                      filter={
                        <TextFilter
                          {...roleFilterProps}
                          filteringPlaceholder="Find role mappings"
                          filteringAriaLabel="Filter role mappings"
                        />
                      }
                      empty={
                        <Box textAlign="center" color="inherit">
                          <b>No role mappings</b>
                        </Box>
                      }
                    />
                    <SpaceBetween direction="horizontal" size="xs">
                      <Button onClick={handleAddRoleMapping}>Add mapping</Button>
                      <Button variant="primary" onClick={handleSaveRoleMappings}>
                        Save
                      </Button>
                    </SpaceBetween>
                  </SpaceBetween>
                </Container>
              </SpaceBetween>
            ),
          },
          {
            label: 'Integration',
            id: 'integration',
            content: (
              <SpaceBetween size="l">
                <Container header={<Header variant="h2" info={<InfoLink content={integrationHelp} ariaLabel="Info about integration details" />}>Connection Details</Header>}>
                  {isSAML ? (
                    <KeyValuePairs
                      columns={1}
                      items={[
                        {
                          label: 'IdP Metadata URL',
                          value: integration?.saml?.metadataUrl ? (
                            <CopyText text={integration.saml.metadataUrl} />
                          ) : '—',
                        },
                        {
                          label: 'App-Specific Metadata URL',
                          value: integration?.saml?.appMetadataUrl ? (
                            <CopyText text={integration.saml.appMetadataUrl} />
                          ) : '—',
                        },
                        {
                          label: 'IdP Entity ID',
                          value: integration?.saml?.entityId ? (
                            <CopyText text={integration.saml.entityId} />
                          ) : '—',
                        },
                        {
                          label: 'SSO URL',
                          value: integration?.saml?.ssoUrl ? (
                            <CopyText text={integration.saml.ssoUrl} />
                          ) : '—',
                        },
                        {
                          label: 'SLO URL',
                          value: integration?.saml?.sloUrl ? (
                            <CopyText text={integration.saml.sloUrl} />
                          ) : '—',
                        },
                      ]}
                    />
                  ) : (
                    <KeyValuePairs
                      columns={1}
                      items={[
                        {
                          label: 'Discovery URL',
                          value: integration?.oidc?.discoveryUrl ? (
                            <CopyText text={integration.oidc.discoveryUrl} />
                          ) : '—',
                        },
                        {
                          label: 'Authorization Endpoint',
                          value: integration?.oidc?.authorizationUrl ? (
                            <CopyText text={integration.oidc.authorizationUrl} />
                          ) : '—',
                        },
                        {
                          label: 'Token Endpoint',
                          value: integration?.oidc?.tokenUrl ? (
                            <CopyText text={integration.oidc.tokenUrl} />
                          ) : '—',
                        },
                        {
                          label: 'JWKS Endpoint',
                          value: integration?.oidc?.jwksUrl ? (
                            <CopyText text={integration.oidc.jwksUrl} />
                          ) : '—',
                        },
                        {
                          label: 'Client ID',
                          value: integration?.oidc?.clientId ? (
                            <CopyText text={integration.oidc.clientId} />
                          ) : '—',
                        },
                      ]}
                    />
                  )}
                </Container>

                {isSAML && (
                  <Container header={<Header variant="h2">Certificate</Header>}>
                    <SpaceBetween size="m">
                      <KeyValuePairs
                        columns={1}
                        items={[
                          {
                            label: 'SHA-256 Fingerprint',
                            value: integration?.saml?.certificateFingerprint ? (
                              <CopyText text={integration.saml.certificateFingerprint} />
                            ) : '—',
                          },
                        ]}
                      />
                      <Button iconName="download">Download Certificate</Button>
                    </SpaceBetween>
                  </Container>
                )}

                <Container header={<Header variant="h2">Quick Start</Header>}>
                  <Tabs
                    tabs={
                      isSAML
                        ? [
                            {
                              id: 'spring',
                              label: 'Spring Boot',
                              content: (
                                <CodeBlock>{`# application.properties
spring.security.saml2.relyingparty.registration.gateway.entity-id=${integration?.saml?.entityId || '{entity-id}'}
spring.security.saml2.relyingparty.registration.gateway.assertingparty.metadata-uri=${integration?.saml?.metadataUrl || '{metadata-url}'}
spring.security.saml2.relyingparty.registration.gateway.assertingparty.singlesignon.url=${integration?.saml?.ssoUrl || '{sso-url}'}
spring.security.saml2.relyingparty.registration.gateway.assertingparty.singlesignon.sign-request=false`}</CodeBlock>
                              ),
                            },
                            {
                              id: 'python',
                              label: 'Python (pysaml2)',
                              content: (
                                <CodeBlock>{`# saml_settings.py
from saml2.config import SPConfig

conf = SPConfig()
conf.load({
    "entityid": "https://your-app.example.com",
    "service": {
        "sp": {
            "endpoints": {
                "assertion_consumer_service": [
                    ("https://your-app.example.com/saml/acs", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                ],
            },
        },
    },
    "metadata": {
        "remote": [{"url": "${integration?.saml?.metadataUrl || '{metadata-url}'}"}],
    },
})`}</CodeBlock>
                              ),
                            },
                            {
                              id: 'ruby',
                              label: 'Ruby (omniauth)',
                              content: (
                                <CodeBlock>{`# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Strategies::SAML,
  idp_sso_service_url:     "${integration?.saml?.ssoUrl || '{sso-url}'}",
  idp_cert_fingerprint:    "${integration?.saml?.certificateFingerprint || '{fingerprint}'}",
  idp_cert_fingerprint_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  issuer:                  "https://your-app.example.com",
  assertion_consumer_service_url: "https://your-app.example.com/auth/saml/callback",
  name_identifier_format:  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"`}</CodeBlock>
                              ),
                            },
                          ]
                        : [
                            {
                              id: 'nextauth',
                              label: 'NextAuth.js',
                              content: (
                                <CodeBlock>{`// app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth";

export const { handlers, auth } = NextAuth({
  providers: [{
    id: "gateway",
    name: "Federation Gateway",
    type: "oidc",
    issuer: "${integration?.oidc?.discoveryUrl?.replace('/.well-known/openid-configuration', '') || '{issuer}'}",
    clientId: "${integration?.oidc?.clientId || '{client-id}'}",
    clientSecret: "", // Public client (PKCE)
    authorization: { params: { scope: "openid email profile" } },
  }],
});`}</CodeBlock>
                              ),
                            },
                            {
                              id: 'express',
                              label: 'Express/Passport',
                              content: (
                                <CodeBlock>{`// app.js
const { Issuer, Strategy } = require('openid-client');

const issuer = await Issuer.discover(
  '${integration?.oidc?.discoveryUrl || '{discovery-url}'}'
);

const client = new issuer.Client({
  client_id: '${integration?.oidc?.clientId || '{client-id}'}',
  token_endpoint_auth_method: 'none',
  response_types: ['code'],
});

passport.use('oidc', new Strategy(
  { client, params: { scope: 'openid email profile' } },
  (tokenSet, userinfo, done) => done(null, userinfo)
));

app.get('/login', passport.authenticate('oidc'));
app.get('/callback', passport.authenticate('oidc', {
  successRedirect: '/',
  failureRedirect: '/login',
}));`}</CodeBlock>
                              ),
                            },
                            {
                              id: 'python',
                              label: 'Python (Authlib)',
                              content: (
                                <CodeBlock>{`# app.py
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='gateway',
    client_id='${integration?.oidc?.clientId || '{client-id}'}',
    server_metadata_url='${integration?.oidc?.discoveryUrl || '{discovery-url}'}',
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oauth.gateway.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = oauth.gateway.authorize_access_token()
    userinfo = token['userinfo']
    return f"Hello {userinfo['email']}"`}</CodeBlock>
                              ),
                            },
                          ]
                    }
                  />
                </Container>

                <Container header={<Header variant="h2">Test</Header>}>
                  <SpaceBetween size="m">
                    <Box>
                      Test the {isSAML ? 'SSO' : 'authentication'} flow to verify your integration
                      is configured correctly.
                    </Box>
                    <SpaceBetween direction="horizontal" size="xs">
                      <Button
                        variant="primary"
                        onClick={handleTestSSO}
                        disabled={application.status !== 'active'}
                      >
                        Test SSO
                      </Button>
                      {isSAML && (
                        <Button
                          onClick={handlePreviewAssertion}
                          loading={previewStatus === 'loading'}
                        >
                          Preview Assertion
                        </Button>
                      )}
                    </SpaceBetween>
                    {previewStatus === 'success' && previewXml && (
                      <Box>
                        <pre
                          style={{
                            backgroundColor: '#f4f4f4',
                            padding: '1rem',
                            borderRadius: '4px',
                            overflow: 'auto',
                            fontSize: '0.75rem',
                            maxHeight: '400px',
                          }}
                        >
                          {previewXml}
                        </pre>
                      </Box>
                    )}
                    {previewStatus === 'error' && (
                      <Alert type="error">Failed to preview assertion.</Alert>
                    )}
                  </SpaceBetween>
                </Container>
              </SpaceBetween>
            ),
          },
        ]}
      />
    </PageLayout>
  );
}
