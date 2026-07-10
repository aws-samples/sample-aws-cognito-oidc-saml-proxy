import { useState } from 'react';
import {
  Table,
  Header,
  Button,
  PropertyFilter,
  Pagination,
  Box,
  Link,
  Modal,
  SpaceBetween,
  FormField,
  Input,
  Select,
  Alert,
  Spinner,
} from '@cloudscape-design/components';
import type { PropertyFilterProps } from '@cloudscape-design/components';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { useIdentitySources, useCreateIdentitySource, useTestConnection, useDiscoverPool } from '../hooks/useIdentitySources';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { identitySourcesPageHelp } from '../help/identitySourcesHelp';
import { getStatusIndicator } from '../utils/status';
import { formatDate } from '../utils/format';

const AWS_REGIONS = [
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-east-2', label: 'US East (Ohio)' },
  { value: 'us-west-1', label: 'US West (N. California)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'eu-north-1', label: 'EU (Stockholm)' },
  { value: 'eu-west-1', label: 'EU (Ireland)' },
  { value: 'eu-west-2', label: 'EU (London)' },
  { value: 'eu-west-3', label: 'EU (Paris)' },
  { value: 'eu-central-1', label: 'EU (Frankfurt)' },
  { value: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)' },
  { value: 'ap-northeast-2', label: 'Asia Pacific (Seoul)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ca-central-1', label: 'Canada (Central)' },
  { value: 'sa-east-1', label: 'South America (Sao Paulo)' },
];

const FILTER_PROPERTIES: PropertyFilterProps.FilteringProperty[] = [
  {
    key: 'status',
    operators: ['='],
    propertyLabel: 'Status',
    groupValuesLabel: 'Status values',
  },
  {
    key: 'region',
    operators: ['='],
    propertyLabel: 'Region',
    groupValuesLabel: 'Region values',
  },
];

export default function IdentitySourcesPage() {
  const { data: identitySources = [], isLoading, isError, error, refetch } = useIdentitySources();
  const createMutation = useCreateIdentitySource();
  const testConnectionMutation = useTestConnection();
  const discoverPoolMutation = useDiscoverPool();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [testingSourceId, setTestingSourceId] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    displayName: '',
    poolId: '',
    region: '',
    clientId: '',
    domain: '',
  });
  const [selectedRegion, setSelectedRegion] = useState<{ value: string; label: string } | null>(null);
  const [discoveredAttributes, setDiscoveredAttributes] = useState<string[]>([]);

  const { items, collectionProps, propertyFilterProps, paginationProps } = useCollection(
    identitySources,
    {
      propertyFiltering: {
        filteringProperties: FILTER_PROPERTIES,
        empty: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No identity sources</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No identity sources to display.
            </Box>
          </Box>
        ),
        noMatch: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No matches</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No identity sources match the filter criteria.
            </Box>
          </Box>
        ),
      },
      pagination: { pageSize: 10 },
      sorting: {},
    }
  );

  const handleCreateSource = async () => {
    try {
      await createMutation.mutateAsync({
        displayName: formData.displayName,
        poolId: formData.poolId,
        region: selectedRegion?.value || '',
        clientId: formData.clientId,
        domain: formData.domain || undefined,
      });
      setShowCreateModal(false);
      setFormData({
        displayName: '',
        poolId: '',
        region: '',
        clientId: '',
        domain: '',
      });
      setSelectedRegion(null);
      setDiscoveredAttributes([]);
      discoverPoolMutation.reset();
    } catch (err) {
      console.error('Failed to create identity source:', err);
    }
  };

  const handleTestConnection = (sourceId: string) => {
    setTestingSourceId(sourceId);
    testConnectionMutation.mutate(sourceId, {
      onSettled: () => setTestingSourceId(null),
    });
  };

  const handleDiscoverPool = async () => {
    if (!formData.poolId.trim() || !selectedRegion) {
      return;
    }

    try {
      const result = await discoverPoolMutation.mutateAsync({
        poolId: formData.poolId,
        region: selectedRegion.value,
      });

      // Auto-fill domain
      if (result.domain) {
        setFormData({ ...formData, domain: result.domain });
      }

      // Store discovered attributes for later use (e.g., claim mapping suggestions)
      if (result.attributes) {
        setDiscoveredAttributes(result.attributes);
      }
    } catch (err) {
      console.error('Failed to discover pool:', err);
    }
  };

  const isFormValid =
    formData.displayName.trim() &&
    formData.poolId.trim() &&
    selectedRegion &&
    formData.clientId.trim();

  if (isError) {
    return (
      <PageLayout
        title="Identity Sources"
        description="Manage Cognito user pool connections"
      >
        <Alert
          type="error"
          header="Unable to load identity sources"
          action={<Button onClick={() => refetch()}>Retry</Button>}
        >
          {error instanceof Error ? error.message : 'An unexpected error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  if (isLoading) {
    return (
      <PageLayout
        title="Identity Sources"
        description="Manage Cognito user pool connections"
      >
        <Box textAlign="center" padding="l">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  return (
    <PageLayout
      title="Identity Sources"
      description="Manage Cognito user pool connections"
      info={<InfoLink content={identitySourcesPageHelp} ariaLabel="Info about identity sources" />}
      actions={
        <Button variant="primary" onClick={() => setShowCreateModal(true)}>
          Add source
        </Button>
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

        <Table
          {...collectionProps}
          variant="borderless"
          loading={isLoading}
          loadingText="Loading identity sources"
          columnDefinitions={[
            {
              id: 'displayName',
              header: 'Display Name',
              cell: (item) => (
                <Link href={`/identity-sources/${item.id}`}>{item.displayName}</Link>
              ),
              sortingField: 'displayName',
              isRowHeader: true,
              width: 260,
              minWidth: 200,
            },
            {
              id: 'type',
              header: 'Type',
              cell: (item) => item.type,
              sortingField: 'type',
              width: 120,
              minWidth: 100,
            },
            {
              id: 'region',
              header: 'Region',
              cell: (item) => item.region,
              sortingField: 'region',
              width: 160,
              minWidth: 130,
            },
            {
              id: 'poolId',
              header: 'Pool ID',
              cell: (item) => item.poolId,
              sortingField: 'poolId',
              width: 220,
              minWidth: 160,
            },
            {
              id: 'status',
              header: 'Status',
              cell: (item) => getStatusIndicator(item.status),
              sortingField: 'status',
              width: 140,
              minWidth: 120,
            },
            {
              id: 'createdAt',
              header: 'Created',
              cell: (item) => formatDate(item.createdAt),
              sortingField: 'createdAt',
              width: 160,
              minWidth: 130,
            },
            {
              id: 'actions',
              header: 'Actions',
              cell: (item) => (
                <Button
                  onClick={() => handleTestConnection(item.id)}
                  loading={testingSourceId === item.id}
                  disabled={!!testingSourceId && testingSourceId !== item.id}
                >
                  Test connection
                </Button>
              ),
              width: 150,
              minWidth: 140,
            },
          ]}
          items={items}
          empty={
            <Box textAlign="center" color="inherit">
              <Box variant="p" color="inherit">
                <b>No identity sources</b>
              </Box>
              <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
                You have not configured any identity sources yet.
              </Box>
              <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                Add source
              </Button>
            </Box>
          }
          filter={
            <PropertyFilter
              {...propertyFilterProps}
              i18nStrings={{
                filteringAriaLabel: 'Filter identity sources',
                dismissAriaLabel: 'Dismiss',
                filteringPlaceholder: 'Filter identity sources by property',
                groupValuesText: 'Values',
                groupPropertiesText: 'Properties',
                operatorsText: 'Operators',
                operationAndText: 'and',
                operationOrText: 'or',
                operatorLessText: 'Less than',
                operatorLessOrEqualText: 'Less than or equal',
                operatorGreaterText: 'Greater than',
                operatorGreaterOrEqualText: 'Greater than or equal',
                operatorContainsText: 'Contains',
                operatorDoesNotContainText: 'Does not contain',
                operatorEqualsText: 'Equals',
                operatorDoesNotEqualText: 'Does not equal',
                editTokenHeader: 'Edit filter',
                propertyText: 'Property',
                operatorText: 'Operator',
                valueText: 'Value',
                cancelActionText: 'Cancel',
                applyActionText: 'Apply',
                allPropertiesLabel: 'All properties',
                tokenLimitShowMore: 'Show more',
                tokenLimitShowFewer: 'Show fewer',
                clearFiltersText: 'Clear filters',
                removeTokenButtonAriaLabel: () => 'Remove token',
                enteredTextLabel: (text) => `Use: "${text}"`,
              }}
              countText={`${items.length} ${items.length === 1 ? 'match' : 'matches'}`}
            />
          }
          header={
            <Header counter={`(${identitySources.length})`}>Identity Sources</Header>
          }
          pagination={<Pagination {...paginationProps} />}
        />

        <Modal
          visible={showCreateModal}
          onDismiss={() => {
            setShowCreateModal(false);
            createMutation.reset();
            discoverPoolMutation.reset();
            setDiscoveredAttributes([]);
          }}
          header="Add identity source"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleCreateSource}
                  disabled={!isFormValid}
                  loading={createMutation.isPending}
                >
                  Add
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="l">
            {createMutation.isError && (
              <Alert type="error" header="Failed to create identity source">
                {createMutation.error instanceof Error ? createMutation.error.message : 'An error occurred'}
              </Alert>
            )}
            <FormField label="Display Name" constraintText="Required">
              <Input
                value={formData.displayName}
                onChange={({ detail }) => setFormData({ ...formData, displayName: detail.value })}
                placeholder="My Cognito Pool"
              />
            </FormField>
            <FormField label="Cognito Pool ID" constraintText="Required">
              <Input
                value={formData.poolId}
                onChange={({ detail }) => setFormData({ ...formData, poolId: detail.value })}
                placeholder="eu-north-1_ABC123DEF"
              />
            </FormField>
            <FormField label="Region" constraintText="Required">
              <Select
                selectedOption={selectedRegion}
                onChange={({ detail }) => {
                  const option = detail.selectedOption as { value: string; label: string };
                  setSelectedRegion(option);
                  setFormData({ ...formData, region: option.value || '' });
                }}
                options={AWS_REGIONS}
                placeholder="Select a region"
                filteringType="auto"
              />
            </FormField>
            <FormField
              label="Auto-Discovery"
              description="Discover the Cognito domain and available attributes from the pool configuration"
            >
              <Button
                onClick={handleDiscoverPool}
                disabled={!formData.poolId.trim() || !selectedRegion}
                loading={discoverPoolMutation.isPending}
                iconName="search"
              >
                Discover pool configuration
              </Button>
            </FormField>
            {discoverPoolMutation.isSuccess && discoverPoolMutation.data && (
              <Alert type="success" dismissible onDismiss={() => discoverPoolMutation.reset()}>
                Discovered domain: {discoverPoolMutation.data.domain}
                {discoverPoolMutation.data.attributes.length > 0 && (
                  <Box variant="p" margin={{ top: 'xs' }}>
                    Found {discoverPoolMutation.data.attributes.length} schema attributes
                  </Box>
                )}
              </Alert>
            )}
            {discoverPoolMutation.isError && (
              <Alert type="error" dismissible onDismiss={() => discoverPoolMutation.reset()}>
                Failed to discover pool configuration. Make sure the Pool ID and Region are correct, and AWS credentials are available.
              </Alert>
            )}
            <FormField label="Client ID" constraintText="Required">
              <Input
                value={formData.clientId}
                onChange={({ detail }) => setFormData({ ...formData, clientId: detail.value })}
                placeholder="1a2b3c4d5e6f7g8h9i0j"
              />
            </FormField>
            <FormField
              label="Cognito Domain"
              description="The Cognito hosted UI domain. Find this in the Cognito console under 'Domain name'."
              constraintText="Format: {prefix}.auth.{region}.amazoncognito.com"
            >
              <Input
                value={formData.domain}
                onChange={({ detail }) => setFormData({ ...formData, domain: detail.value })}
                placeholder="my-app.auth.eu-north-1.amazoncognito.com"
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      </SpaceBetween>
    </PageLayout>
  );
}
