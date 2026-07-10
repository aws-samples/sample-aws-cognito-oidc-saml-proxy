import { authFetch } from '../auth';
import {
  Container,
  Header,
  SpaceBetween,
  FormField,
  Input,
  Select,
  Button,
  Spinner,
  Box,
  Alert,
  Toggle,
  Multiselect,
  KeyValuePairs,
  Tabs,
} from '@cloudscape-design/components';
import { useState, useEffect } from 'react';
import { useSettings } from '../hooks/useSettings';
import { useQueryClient } from '@tanstack/react-query';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { tenantProfileHelp, protocolDefaultsHelp, gatewayInfoHelp } from '../help/settingsHelp';
import CopyText from '../components/CopyText';

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data: settings, isLoading, error } = useSettings();

  const [displayName, setDisplayName] = useState('');
  const [maxApps, setMaxApps] = useState('');
  const [maxAuthsPerMonth, setMaxAuthsPerMonth] = useState('');
  const [sessionDuration, setSessionDuration] = useState('');
  const [signResponse, setSignResponse] = useState(false);
  const [signAssertion, setSignAssertion] = useState(false);
  const [nameIdFormat, setNameIdFormat] = useState<{ label: string; value: string } | null>(null);
  const [idTokenLifetime, setIdTokenLifetime] = useState('');
  const [accessTokenLifetime, setAccessTokenLifetime] = useState('');
  const [defaultScopes, setDefaultScopes] = useState<Array<{ label: string; value: string }>>([]);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const nameIdFormatOptions = [
    { label: 'Persistent', value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' },
    { label: 'Transient', value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' },
    { label: 'Email Address', value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
    { label: 'Unspecified', value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified' },
  ];

  const scopeOptions = [
    { label: 'openid', value: 'openid' },
    { label: 'email', value: 'email' },
    { label: 'profile', value: 'profile' },
    { label: 'offline_access', value: 'offline_access' },
  ];

  useEffect(() => {
    if (settings?.tenant) {
      setDisplayName(settings.tenant.displayName || '');
      setMaxApps(String(settings.tenant.maxApps || 0));
      setMaxAuthsPerMonth(String(settings.tenant.maxAuthsPerMonth || 0));
      setSessionDuration(String(settings.tenant.defaultSessionDurationSec || 3600));
      setSignResponse(settings.tenant.defaultSignResponse ?? true);
      setSignAssertion(settings.tenant.defaultSignAssertion ?? true);

      const matchedFormat = nameIdFormatOptions.find(
        (opt) => opt.value === settings.tenant.defaultNameIdFormat
      );
      setNameIdFormat(matchedFormat || nameIdFormatOptions[0]);

      setIdTokenLifetime(String(settings.tenant.defaultIdTokenLifetimeSec || 3600));
      setAccessTokenLifetime(String(settings.tenant.defaultAccessTokenLifetimeSec || 3600));

      const scopes = (settings.tenant.defaultScopes || []).map((scope: string) => ({
        label: scope,
        value: scope,
      }));
      setDefaultScopes(scopes);
    }
  }, [settings]);

  const handleSaveTenant = async () => {
    if (!settings?.tenant?.slug) return;

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);

    try {
      const res = await authFetch(`/api/v1/tenants/${settings.tenant.slug}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          displayName,
          maxApps: parseInt(maxApps, 10),
          maxAuthsPerMonth: parseInt(maxAuthsPerMonth, 10),
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to update tenant: ${res.status}`);
      }

      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveDefaults = async () => {
    if (!settings?.tenant?.slug) return;

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);

    try {
      const res = await authFetch(`/api/v1/tenants/${settings.tenant.slug}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          defaultSessionDurationSec: parseInt(sessionDuration, 10),
          defaultSignResponse: signResponse,
          defaultSignAssertion: signAssertion,
          defaultNameIdFormat: nameIdFormat?.value || nameIdFormatOptions[0].value,
          defaultIdTokenLifetimeSec: parseInt(idTokenLifetime, 10),
          defaultAccessTokenLifetimeSec: parseInt(accessTokenLifetime, 10),
          defaultScopes: defaultScopes.map((s) => s.value),
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to update defaults: ${res.status}`);
      }

      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  if (isLoading) {
    return (
      <PageLayout
        title="Gateway Configuration"
        description="Manage tenant settings and protocol defaults"
      >
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (error) {
    return (
      <PageLayout
        title="Gateway Configuration"
        description="Manage tenant settings and protocol defaults"
      >
        <Alert type="error" header="Failed to load settings">
          {error instanceof Error ? error.message : 'An error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  return (
    <PageLayout
      title="Gateway Configuration"
      description="Manage tenant settings and protocol defaults"
    >
      <SpaceBetween size="l">
        {saveSuccess && (
          <Alert type="success" dismissible onDismiss={() => setSaveSuccess(false)}>
            Settings saved successfully
          </Alert>
        )}

        {saveError && (
          <Alert type="error" dismissible onDismiss={() => setSaveError(null)}>
            {saveError}
          </Alert>
        )}

        <Container header={<Header variant="h2" info={<InfoLink content={tenantProfileHelp} ariaLabel="Info about the tenant profile" />}>Tenant Profile</Header>}>
          <SpaceBetween size="l">
            <FormField
              label="Display Name"
              description="The display name for this tenant"
            >
              <Input
                value={displayName}
                onChange={(event) => setDisplayName(event.detail.value)}
                placeholder="My Organization"
              />
            </FormField>

            <FormField
              label="Plan"
              description="Current subscription plan"
            >
              <Input
                value={settings?.tenant?.plan || '-'}
                readOnly
                disabled
              />
            </FormField>

            <FormField
              label="Max Applications"
              description="Maximum number of applications allowed"
            >
              <Input
                value={maxApps}
                onChange={(event) => setMaxApps(event.detail.value)}
                type="number"
                inputMode="numeric"
              />
            </FormField>

            <FormField
              label="Max Authentications Per Month"
              description="Monthly authentication limit"
            >
              <Input
                value={maxAuthsPerMonth}
                onChange={(event) => setMaxAuthsPerMonth(event.detail.value)}
                type="number"
                inputMode="numeric"
              />
            </FormField>

            <Box float="right">
              <Button
                variant="primary"
                onClick={handleSaveTenant}
                loading={saving}
              >
                Save
              </Button>
            </Box>
          </SpaceBetween>
        </Container>

        <Container header={<Header variant="h2" info={<InfoLink content={protocolDefaultsHelp} ariaLabel="Info about protocol defaults" />}>Protocol Defaults</Header>}>
          <SpaceBetween size="l">
            <Tabs
              tabs={[
                {
                  label: 'SAML Defaults',
                  id: 'saml',
                  content: (
                    <SpaceBetween size="l">
                      <FormField
                        label="Session Duration (seconds)"
                        description="Default session duration for SAML assertions"
                      >
                        <Input
                          value={sessionDuration}
                          onChange={(event) => setSessionDuration(event.detail.value)}
                          type="number"
                          inputMode="numeric"
                        />
                      </FormField>

                      <FormField
                        label="Sign Response"
                        description="Sign the SAML response by default"
                      >
                        <Toggle
                          checked={signResponse}
                          onChange={(event) => setSignResponse(event.detail.checked)}
                        >
                          {signResponse ? 'Enabled' : 'Disabled'}
                        </Toggle>
                      </FormField>

                      <FormField
                        label="Sign Assertion"
                        description="Sign the SAML assertion by default"
                      >
                        <Toggle
                          checked={signAssertion}
                          onChange={(event) => setSignAssertion(event.detail.checked)}
                        >
                          {signAssertion ? 'Enabled' : 'Disabled'}
                        </Toggle>
                      </FormField>

                      <FormField
                        label="NameID Format"
                        description="Default NameID format for SAML assertions"
                      >
                        <Select
                          selectedOption={nameIdFormat}
                          onChange={(event) => {
                            const option = event.detail.selectedOption;
                            if (option && option.label && option.value) {
                              setNameIdFormat({ label: option.label, value: option.value });
                            }
                          }}
                          options={nameIdFormatOptions}
                        />
                      </FormField>
                    </SpaceBetween>
                  ),
                },
                {
                  label: 'OIDC Defaults',
                  id: 'oidc',
                  content: (
                    <SpaceBetween size="l">
                      <FormField
                        label="ID Token Lifetime (seconds)"
                        description="Default lifetime for ID tokens"
                      >
                        <Input
                          value={idTokenLifetime}
                          onChange={(event) => setIdTokenLifetime(event.detail.value)}
                          type="number"
                          inputMode="numeric"
                        />
                      </FormField>

                      <FormField
                        label="Access Token Lifetime (seconds)"
                        description="Default lifetime for access tokens"
                      >
                        <Input
                          value={accessTokenLifetime}
                          onChange={(event) => setAccessTokenLifetime(event.detail.value)}
                          type="number"
                          inputMode="numeric"
                        />
                      </FormField>

                      <FormField
                        label="Default Scopes"
                        description="Default OAuth 2.0 scopes"
                      >
                        <Multiselect
                          selectedOptions={defaultScopes}
                          onChange={(event) => {
                            const options = Array.from(event.detail.selectedOptions).map(opt => ({
                              label: opt.label || '',
                              value: opt.value || '',
                            }));
                            setDefaultScopes(options);
                          }}
                          options={scopeOptions}
                          placeholder="Select scopes"
                        />
                      </FormField>
                    </SpaceBetween>
                  ),
                },
              ]}
            />

            <Box float="right">
              <Button
                variant="primary"
                onClick={handleSaveDefaults}
                loading={saving}
              >
                Save Defaults
              </Button>
            </Box>
          </SpaceBetween>
        </Container>

        <Container header={<Header variant="h2" info={<InfoLink content={gatewayInfoHelp} ariaLabel="Info about gateway information" />}>Gateway Information</Header>}>
          <KeyValuePairs
            columns={2}
            items={[
              {
                label: 'Entity ID',
                value: settings?.gateway?.entityId || '-',
              },
              {
                label: 'Base URL',
                value: settings?.gateway?.baseUrl || '-',
              },
              {
                label: 'Tenant Slug',
                value: settings?.tenant?.slug || '-',
              },
              {
                label: 'KMS Key ID',
                value: settings?.gateway?.kmsKeyId || '-',
              },
              {
                label: 'Backup KMS Key ID',
                value: settings?.gateway?.kmsKeyIdBackup ? (
                  <CopyText text={settings.gateway.kmsKeyIdBackup} />
                ) : (
                  'Not configured'
                ),
              },
              {
                label: 'SAML Metadata URL',
                value: settings?.gateway?.samlMetadataUrl ? (
                  <CopyText text={settings.gateway.samlMetadataUrl} />
                ) : (
                  '-'
                ),
              },
              {
                label: 'OIDC Discovery URL',
                value: settings?.gateway?.oidcDiscoveryUrl ? (
                  <CopyText text={settings.gateway.oidcDiscoveryUrl} />
                ) : (
                  '-'
                ),
              },
            ]}
          />
        </Container>
      </SpaceBetween>
    </PageLayout>
  );
}
