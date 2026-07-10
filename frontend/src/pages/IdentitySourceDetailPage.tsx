import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Header,
  SpaceBetween,
  Button,
  Tabs,
  KeyValuePairs,
  Alert,
  Spinner,
  Box,
  Table,
  Link,
  Modal,
  FormField,
  Input,
  Badge,
} from '@cloudscape-design/components';
import {
  useIdentitySource,
  useUpdateIdentitySource,
  useDeleteIdentitySource,
  useTestConnection,
} from '../hooks/useIdentitySources';
import { useApplications } from '../hooks/useApplications';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { sourceDetailHelp, sourceAppsHelp } from '../help/identitySourcesHelp';
import { getStatusIndicator, getProtocolBadge } from '../utils/status';
import { formatDateTime } from '../utils/format';

export default function IdentitySourceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: source, isLoading, error } = useIdentitySource(id!);
  const { data: applications = [] } = useApplications();
  const updateMutation = useUpdateIdentitySource();
  const deleteMutation = useDeleteIdentitySource();
  const testConnectionMutation = useTestConnection();

  const [activeTabId, setActiveTabId] = useState('config');
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState<{
    displayName: string;
    poolId: string;
    region: string;
    domain: string;
    clientId: string;
  }>({
    displayName: '',
    poolId: '',
    region: '',
    domain: '',
    clientId: '',
  });

  const relatedApps = applications.filter((app) => app.sourceId === id);

  if (isLoading) {
    return (
      <PageLayout title="Identity Source" description="Loading...">
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (error || !source) {
    return (
      <PageLayout title="Identity Source" description="Error">
        <Alert type="error" header="Error loading identity source">
          {error instanceof Error ? error.message : 'Identity source not found'}
        </Alert>
      </PageLayout>
    );
  }

  if (!editMode && formData.displayName === '') {
    setFormData({
      displayName: source.displayName,
      poolId: source.poolId,
      region: source.region,
      domain: source.domain,
      clientId: source.clientId,
    });
  }

  const handleSave = async () => {
    try {
      await updateMutation.mutateAsync({
        id: id!,
        data: formData,
      });
      setEditMode(false);
    } catch (err) {
      console.error('Failed to update identity source:', err);
    }
  };

  const handleDelete = async () => {
    try {
      await deleteMutation.mutateAsync(id!);
      navigate('/identity-sources');
    } catch (err) {
      console.error('Failed to delete identity source:', err);
    }
  };

  const handleTestConnection = async () => {
    testConnectionMutation.mutate(id!);
  };

  return (
    <PageLayout
      title={source.displayName}
      description={getStatusIndicator(source.status)}
      actions={
        <SpaceBetween direction="horizontal" size="xs">
          <Button onClick={handleTestConnection} loading={testConnectionMutation.isPending}>
            Test Connection
          </Button>
          <Button onClick={() => setShowDeleteModal(true)}>Delete</Button>
        </SpaceBetween>
      }
    >
      <SpaceBetween size="l">
        {testConnectionMutation.isSuccess && testConnectionMutation.data && (
          <Alert
            type={testConnectionMutation.data.reachable ? 'success' : 'error'}
            dismissible
            onDismiss={() => testConnectionMutation.reset()}
            header={testConnectionMutation.data.reachable ? 'Connection successful' : 'Connection failed'}
          >
            {testConnectionMutation.data.reachable
              ? `Response time: ${testConnectionMutation.data.latencyMs}ms`
              : testConnectionMutation.data.error || 'Unable to connect to identity source'}
          </Alert>
        )}

        {updateMutation.isError && (
          <Alert
            type="error"
            dismissible
            onDismiss={() => updateMutation.reset()}
            header="Failed to update identity source"
          >
            {updateMutation.error instanceof Error ? updateMutation.error.message : 'An error occurred'}
          </Alert>
        )}

        <Tabs
          activeTabId={activeTabId}
          onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
          tabs={[
            {
              id: 'config',
              label: 'Configuration',
              content: (
                <Container
                  header={
                    <Header
                      variant="h2"
                      info={<InfoLink content={sourceDetailHelp} ariaLabel="Info about this identity source" />}
                      actions={
                        editMode ? (
                          <SpaceBetween direction="horizontal" size="xs">
                            <Button onClick={() => setEditMode(false)}>Cancel</Button>
                            <Button variant="primary" onClick={handleSave} loading={updateMutation.isPending}>
                              Save
                            </Button>
                          </SpaceBetween>
                        ) : (
                          <Button onClick={() => setEditMode(true)}>Edit</Button>
                        )
                      }
                    >
                      Details
                    </Header>
                  }
                >
                  {editMode ? (
                    <SpaceBetween size="l">
                      <FormField label="Display Name">
                        <Input
                          value={formData.displayName}
                          onChange={({ detail }) => setFormData({ ...formData, displayName: detail.value })}
                        />
                      </FormField>
                      <FormField label="Pool ID" description="Cannot be changed">
                        <Input value={formData.poolId} disabled />
                      </FormField>
                      <FormField label="Region">
                        <Input
                          value={formData.region}
                          onChange={({ detail }) => setFormData({ ...formData, region: detail.value })}
                        />
                      </FormField>
                      <FormField label="Domain">
                        <Input
                          value={formData.domain}
                          onChange={({ detail }) => setFormData({ ...formData, domain: detail.value })}
                        />
                      </FormField>
                      <FormField label="Client ID">
                        <Input
                          value={formData.clientId}
                          onChange={({ detail }) => setFormData({ ...formData, clientId: detail.value })}
                        />
                      </FormField>
                    </SpaceBetween>
                  ) : (
                    <KeyValuePairs
                      columns={2}
                      items={[
                        {
                          type: 'group',
                          items: [
                            { label: 'ID', value: source.id },
                            { label: 'Display Name', value: source.displayName },
                            { label: 'Type', value: <Badge color="blue">{source.type}</Badge> },
                            { label: 'Pool ID', value: source.poolId },
                            { label: 'Region', value: source.region },
                          ],
                        },
                        {
                          type: 'group',
                          items: [
                            { label: 'Domain', value: source.domain },
                            { label: 'Client ID', value: source.clientId },
                            {
                              label: 'Status',
                              value: getStatusIndicator(source.status),
                            },
                            {
                              label: 'Created',
                              value: formatDateTime(source.createdAt),
                            },
                            {
                              label: 'Updated',
                              value: source.updatedAt ? formatDateTime(source.updatedAt) : 'Never',
                            },
                          ],
                        },
                      ]}
                    />
                  )}
                </Container>
              ),
            },
            {
              id: 'applications',
              label: `Applications (${relatedApps.length})`,
              content: (
                <Table
                  columnDefinitions={[
                    {
                      id: 'displayName',
                      header: 'Name',
                      cell: (item) => <Link href={`/applications/${item.id}`}>{item.displayName}</Link>,
                      isRowHeader: true,
                      width: 280,
                      minWidth: 200,
                    },
                    {
                      id: 'protocol',
                      header: 'Protocol',
                      cell: (item) => getProtocolBadge(item.protocol),
                      width: 120,
                      minWidth: 100,
                    },
                    {
                      id: 'status',
                      header: 'Status',
                      cell: (item) => getStatusIndicator(item.status),
                      width: 140,
                      minWidth: 120,
                    },
                  ]}
                  items={relatedApps}
                  empty={
                    <Box textAlign="center" color="inherit">
                      <Box variant="p" color="inherit">
                        <b>No applications</b>
                      </Box>
                      <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
                        No applications are using this identity source.
                      </Box>
                    </Box>
                  }
                  header={<Header variant="h2" info={<InfoLink content={sourceAppsHelp} ariaLabel="Info about applications using this source" />}>Applications</Header>}
                />
              ),
            },
          ]}
        />

        <Modal
          visible={showDeleteModal}
          onDismiss={() => setShowDeleteModal(false)}
          header="Delete identity source"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setShowDeleteModal(false)}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={handleDelete} loading={deleteMutation.isPending}>
                  Delete
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          Are you sure you want to delete <b>{source.displayName}</b>? This action cannot be undone.
          {relatedApps.length > 0 && (
            <Alert type="warning" header="Warning">
              This identity source is used by {relatedApps.length} application{relatedApps.length !== 1 ? 's' : ''}. Deleting it may break those applications.
            </Alert>
          )}
        </Modal>
      </SpaceBetween>
    </PageLayout>
  );
}
