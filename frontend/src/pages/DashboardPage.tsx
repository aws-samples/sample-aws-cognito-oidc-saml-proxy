import {
  SpaceBetween,
  Container,
  Box,
  Header,
  StatusIndicator,
  Button,
  Spinner,
  Alert,
  Table,
  KeyValuePairs,
  Link,
  ProgressBar,
  ExpandableSection,
} from '@cloudscape-design/components';
import { useNavigate } from 'react-router-dom';
import {
  useDashboardStats,
  useRecentEvents,
  useGatewayInfo,
} from '../hooks/useDashboardData';
import { useApplications } from '../hooks/useApplications';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { dashboardOverviewHelp, dashboardEventsHelp } from '../help/miscHelp';
import CopyText from '../components/CopyText';
import { getStatusIndicator } from '../utils/status';
import { formatRelative } from '../utils/format';
import type { FlowStep } from '../hooks/useDashboardData';

function deriveEventStatus(stepType: string): string {
  const s = stepType.toLowerCase();
  if (s.includes('error') || s.includes('fail')) return 'error';
  if (s.includes('success') || s.includes('complete')) return 'success';
  return 'info';
}

function SetupChecklist({
  sourceCount,
  appCount,
  hasApp,
  firstAppId,
}: {
  sourceCount: number;
  appCount: number;
  hasApp: boolean;
  firstAppId: string | undefined;
}) {
  const navigate = useNavigate();

  return (
    <Alert type="info" header="Complete setup to start federating identities">
      <SpaceBetween size="m">
        <Box>
          <SpaceBetween size="s" direction="horizontal" alignItems="center">
            <StatusIndicator type={sourceCount > 0 ? 'success' : 'pending'}>
              {sourceCount > 0 ? 'Complete' : 'Pending'}
            </StatusIndicator>
            <Box variant="span" fontWeight="bold">
              Step 1: Add an identity source
            </Box>
            {sourceCount === 0 && (
              <Button onClick={() => navigate('/identity-sources')}>
                Go to Identity Sources
              </Button>
            )}
          </SpaceBetween>
        </Box>

        <Box>
          <SpaceBetween size="s" direction="horizontal" alignItems="center">
            <StatusIndicator type={appCount > 0 ? 'success' : 'pending'}>
              {appCount > 0 ? 'Complete' : 'Pending'}
            </StatusIndicator>
            <Box variant="span" fontWeight="bold">
              Step 2: Register your first application
            </Box>
            {appCount === 0 && (
              <Button onClick={() => navigate('/applications/new')}>
                Register Application
              </Button>
            )}
          </SpaceBetween>
        </Box>

        {hasApp && firstAppId && (
          <Box>
            <SpaceBetween size="s" direction="horizontal" alignItems="center">
              <StatusIndicator type="pending">Pending</StatusIndicator>
              <Box variant="span" fontWeight="bold">
                Step 3: Test authentication
              </Box>
              <Button onClick={() => navigate(`/applications/${firstAppId}`)}>
                View Application
              </Button>
            </SpaceBetween>
          </Box>
        )}
      </SpaceBetween>
    </Alert>
  );
}

function OverviewMetrics({
  sourceCount,
  appCount,
  certDaysRemaining,
  certIsExpired,
  totalAuths,
}: {
  sourceCount: number;
  appCount: number;
  certDaysRemaining: number;
  certIsExpired: boolean;
  totalAuths: number;
}) {
  const certProgressValue = Math.max(0, Math.min(100, (certDaysRemaining / 730) * 100));
  const certStatus = certIsExpired || certDaysRemaining < 30 ? 'error' : certDaysRemaining < 90 ? 'in-progress' : 'success';

  return (
    <Container header={<Header variant="h2" info={<InfoLink content={dashboardOverviewHelp} ariaLabel="Info about the overview metrics" />}>Overview</Header>}>
      <KeyValuePairs
        columns={4}
        items={[
          {
            type: 'group',
            items: [
              {
                label: 'Identity Sources',
                value: (
                  <Link variant="awsui-value-large" href="/identity-sources">
                    {sourceCount}
                  </Link>
                ),
              },
            ],
          },
          {
            type: 'group',
            items: [
              {
                label: 'Applications',
                value: (
                  <Link variant="awsui-value-large" href="/applications">
                    {appCount}
                  </Link>
                ),
              },
            ],
          },
          {
            type: 'group',
            items: [
              {
                label: 'Certificate Expiry',
                value: (
                  <ProgressBar
                    value={certProgressValue}
                    label={`${certDaysRemaining} days remaining`}
                    variant="key-value"
                    status={certStatus}
                  />
                ),
              },
            ],
          },
          {
            type: 'group',
            items: [
              {
                label: 'Total Authentications',
                value: (
                  <Box variant="awsui-value-large">
                    {totalAuths.toLocaleString()}
                  </Box>
                ),
              },
            ],
          },
        ]}
      />
    </Container>
  );
}

const EVENTS_COLUMN_DEFINITIONS = [
  {
    id: 'timestamp',
    header: 'Timestamp',
    cell: (item: FlowStep) => formatRelative(item.timestamp),
    sortingField: 'timestamp' as const,
  },
  {
    id: 'eventType',
    header: 'Event Type',
    cell: (item: FlowStep) => item.stepType,
  },
  {
    id: 'user',
    header: 'User',
    cell: (item: FlowStep) => item.userId || '-',
  },
  {
    id: 'application',
    header: 'Application',
    cell: (item: FlowStep) => item.spEntityId || '-',
  },
  {
    id: 'status',
    header: 'Status',
    cell: (item: FlowStep) => getStatusIndicator(deriveEventStatus(item.stepType)),
  },
];

function RecentEventsTable({
  events,
  isLoading,
}: {
  events: FlowStep[];
  isLoading: boolean;
}) {
  return (
    <Container header={<Header variant="h2" info={<InfoLink content={dashboardEventsHelp} ariaLabel="Info about recent events" />}>Recent Events</Header>}>
      <Table
        columnDefinitions={EVENTS_COLUMN_DEFINITIONS}
        items={events}
        loading={isLoading}
        loadingText="Loading events"
        empty={
          <Box textAlign="center" color="text-body-secondary" padding="l">
            No authentication events recorded yet. Events appear as users
            authenticate.
          </Box>
        }
        variant="embedded"
      />
    </Container>
  );
}

function GatewayInformation({
  entityId,
  baseUrl,
  tenantSlug,
  kmsKeyId,
  samlMetadataUrl,
  oidcDiscoveryUrl,
  isLoading,
  error,
}: {
  entityId: string;
  baseUrl: string;
  tenantSlug: string;
  kmsKeyId: string;
  samlMetadataUrl: string;
  oidcDiscoveryUrl: string;
  isLoading: boolean;
  error: Error | null;
}) {
  if (isLoading) {
    return (
      <ExpandableSection
        defaultExpanded={false}
        variant="container"
        headerText="Gateway Information"
      >
        <Box textAlign="center" padding="l">
          <Spinner />
        </Box>
      </ExpandableSection>
    );
  }

  if (error) {
    return (
      <ExpandableSection
        defaultExpanded={false}
        variant="container"
        headerText="Gateway Information"
      >
        <Alert type="warning" header="Failed to load gateway information">
          {error.message}
        </Alert>
      </ExpandableSection>
    );
  }

  return (
    <ExpandableSection
      defaultExpanded={false}
      variant="container"
      headerText="Gateway Information"
    >
      <KeyValuePairs
        columns={2}
        items={[
          { label: 'Entity ID', value: entityId || '-' },
          { label: 'Base URL', value: baseUrl || '-' },
          { label: 'Tenant Slug', value: tenantSlug || '-' },
          { label: 'KMS Key ID', value: kmsKeyId || '-' },
          {
            label: 'SAML Metadata URL',
            value: samlMetadataUrl ? <CopyText text={samlMetadataUrl} /> : '-',
          },
          {
            label: 'OIDC Discovery URL',
            value: oidcDiscoveryUrl ? <CopyText text={oidcDiscoveryUrl} /> : '-',
          },
        ]}
      />
    </ExpandableSection>
  );
}

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading, error: statsError } = useDashboardStats();
  const { data: events = [], isLoading: eventsLoading } = useRecentEvents();
  const { data: gatewayInfo, isLoading: gatewayLoading, error: gatewayError } = useGatewayInfo();
  const { data: apps = [] } = useApplications();

  if (statsLoading) {
    return (
      <PageLayout title="Overview" description="Federation gateway health and activity">
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (statsError) {
    return (
      <PageLayout title="Overview" description="Federation gateway health and activity">
        <Alert type="error" header="Failed to load dashboard">
          {statsError instanceof Error ? statsError.message : 'An error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  const isFirstRun = stats !== undefined && (stats.sourceCount === 0 || stats.appCount === 0);
  const firstApp = apps.length > 0 ? apps[0] : undefined;

  return (
    <PageLayout title="Overview" description="Federation gateway health and activity">
      <SpaceBetween size="l">
        {isFirstRun && stats && (
          <SetupChecklist
            sourceCount={stats.sourceCount}
            appCount={stats.appCount}
            hasApp={apps.length > 0}
            firstAppId={firstApp?.id}
          />
        )}

        {stats && (
          <OverviewMetrics
            sourceCount={stats.sourceCount}
            appCount={stats.appCount}
            certDaysRemaining={stats.certDaysRemaining}
            certIsExpired={stats.certIsExpired}
            totalAuths={stats.totalAuths}
          />
        )}

        <RecentEventsTable events={events} isLoading={eventsLoading} />

        <GatewayInformation
          entityId={gatewayInfo?.gateway?.entityId ?? ''}
          baseUrl={gatewayInfo?.gateway?.baseUrl ?? ''}
          tenantSlug={gatewayInfo?.tenant?.slug ?? ''}
          kmsKeyId={gatewayInfo?.gateway?.kmsKeyId ?? ''}
          samlMetadataUrl={gatewayInfo?.gateway?.samlMetadataUrl ?? ''}
          oidcDiscoveryUrl={gatewayInfo?.gateway?.oidcDiscoveryUrl ?? ''}
          isLoading={gatewayLoading}
          error={gatewayError as Error | null}
        />
      </SpaceBetween>
    </PageLayout>
  );
}
