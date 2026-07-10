import {
  Table,
  Header,
  SpaceBetween,
  Pagination,
  PropertyFilter,
  Box,
  Link,
  Spinner,
  Alert,
  Button,
  Container,
  KeyValuePairs,
  StatusIndicator,
  Modal,
} from '@cloudscape-design/components';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { useState } from 'react';
import { useAuditLog, useFlowDetail, type FlowStep } from '../hooks/useAuditLog';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { auditLogPageHelp } from '../help/miscHelp';
import { getStatusIndicator } from '../utils/status';
import { formatRelative } from '../utils/format';

export default function AuditLogPage() {
  const { data: auditEvents = [], isLoading, error, refetch } = useAuditLog();
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);
  const { data: flowDetail, isLoading: isFlowLoading } = useFlowDetail(selectedFlowId);

  const { items, collectionProps, propertyFilterProps, paginationProps } =
    useCollection(auditEvents, {
      propertyFiltering: {
        filteringProperties: [
          {
            key: 'stepType',
            propertyLabel: 'Event Type',
            groupValuesLabel: 'Event Type values',
            operators: ['=', '!=', ':', '!:'],
          },
          {
            key: 'spEntityId',
            propertyLabel: 'Application',
            groupValuesLabel: 'Application values',
            operators: ['=', '!=', ':', '!:'],
          },
          {
            key: 'userId',
            propertyLabel: 'User',
            groupValuesLabel: 'User values',
            operators: ['=', '!=', ':', '!:'],
          },
        ],
        empty: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No authentication events</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No authentication events recorded. Events are logged when users
              authenticate through the gateway.
            </Box>
          </Box>
        ),
        noMatch: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No matches</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No audit events match the filter criteria.
            </Box>
          </Box>
        ),
      },
      pagination: { pageSize: 20 },
      sorting: {},
    });

  if (error) {
    return (
      <PageLayout title="Audit Log" description="Authentication flow traces and events">
        <Alert
          type="error"
          header="Failed to load audit log"
          action={<Button onClick={() => refetch()}>Retry</Button>}
        >
          {error instanceof Error ? error.message : 'An unexpected error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  const truncateFlowId = (flowId: string) => {
    if (flowId.length <= 12) return flowId;
    return `${flowId.slice(0, 8)}...${flowId.slice(-4)}`;
  };

  return (
    <PageLayout title="Audit Log" description="Authentication flow traces and events" info={<InfoLink content={auditLogPageHelp} ariaLabel="Info about the audit log" />}>
      <SpaceBetween size="l">
        <Table
          {...collectionProps}
          variant="borderless"
          loading={isLoading}
          loadingText="Loading audit events"
          columnDefinitions={[
            {
              id: 'timestamp',
              header: 'Timestamp',
              cell: (item) => formatRelative(item.timestamp),
              sortingField: 'timestamp',
              width: 160,
              minWidth: 130,
            },
            {
              id: 'flowId',
              header: 'Flow ID',
              cell: (item) => (
                <Link onFollow={() => setSelectedFlowId(item.flowId)}>
                  {truncateFlowId(item.flowId)}
                </Link>
              ),
              width: 160,
              minWidth: 130,
            },
            {
              id: 'stepType',
              header: 'Event Type',
              cell: (item) => item.stepType || '\u2014',
              sortingField: 'stepType',
              width: 180,
              minWidth: 140,
            },
            {
              id: 'userId',
              header: 'User',
              cell: (item) => item.userId || '\u2014',
              sortingField: 'userId',
              width: 180,
              minWidth: 140,
            },
            {
              id: 'spEntityId',
              header: 'Application',
              cell: (item) => item.spEntityId || '\u2014',
              sortingField: 'spEntityId',
              width: 200,
              minWidth: 150,
            },
            {
              id: 'status',
              header: 'Status',
              cell: (item) => {
                const status = item.payload?.status;
                if (!status) return '\u2014';
                return getStatusIndicator(status);
              },
              width: 140,
              minWidth: 120,
            },
          ]}
          items={items}
          onRowClick={(event) => setSelectedFlowId(event.detail.item.flowId)}
          empty={
            <Box textAlign="center" color="inherit">
              <Box variant="p" color="inherit">
                <b>No authentication events</b>
              </Box>
              <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
                No authentication events recorded. Events are logged when users
                authenticate through the gateway.
              </Box>
            </Box>
          }
          filter={
            <PropertyFilter
              {...propertyFilterProps}
              i18nStrings={{
                filteringAriaLabel: 'Filter audit events',
                dismissAriaLabel: 'Dismiss',
                filteringPlaceholder: 'Filter events by property',
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
          header={<Header counter={`(${auditEvents.length})`}>Audit Events</Header>}
          pagination={<Pagination {...paginationProps} />}
        />

        {selectedFlowId && (
          <Modal
            visible={!!selectedFlowId}
            onDismiss={() => setSelectedFlowId(null)}
            size="large"
            header={
              <Header
                variant="h2"
                description={(() => {
                  if (!flowDetail?.steps?.length) return '';
                  const steps = flowDetail.steps;
                  const protocol = steps[0]?.stepType?.startsWith('oidc') ? 'OIDC' : 'SAML';
                  const success = steps.some((s: any) => s.payload?.status === 'success');
                  return `${protocol} authentication flow \u2014 ${success ? 'Completed successfully' : 'In progress'}`;
                })()}
              >
                {(() => {
                  if (!flowDetail?.steps?.length) return `Flow ${truncateFlowId(selectedFlowId)}`;
                  const user = flowDetail.steps.find((s: any) => s.userId)?.userId;
                  return user || `Flow ${truncateFlowId(selectedFlowId)}`;
                })()}
              </Header>
            }
          >
            {isFlowLoading ? (
              <Box textAlign="center" padding="l">
                <Spinner size="large" />
              </Box>
            ) : flowDetail ? (
              <SpaceBetween size="l">
                <KeyValuePairs
                  columns={4}
                  items={(() => {
                    const steps = flowDetail.steps || [];
                    const user = steps.find((s: any) => s.userId)?.userId;
                    const app = steps.find((s: any) => s.spEntityId)?.spEntityId;
                    const protocol = steps[0]?.stepType?.startsWith('oidc') ? 'OIDC' : 'SAML';
                    const tenant = steps.find((s: any) => s.payload?.tenant)?.payload?.tenant;
                    const success = steps.some((s: any) => s.payload?.status === 'success');
                    return [
                      { type: 'group' as const, items: [{ label: 'User', value: user || '\u2014' }] },
                      { type: 'group' as const, items: [{ label: 'Application', value: app ? (app.length > 40 ? app.substring(0, 37) + '...' : app) : '\u2014' }] },
                      { type: 'group' as const, items: [{ label: 'Protocol', value: protocol }] },
                      { type: 'group' as const, items: [{ label: 'Result', value: success ? (
                        <StatusIndicator type="success">Success</StatusIndicator>
                      ) : (
                        <StatusIndicator type="in-progress">In progress</StatusIndicator>
                      ) }] },
                    ];
                  })()}
                />

                <Box variant="h3">Flow Timeline</Box>
                <SpaceBetween size="xs">
                  {(flowDetail.steps || []).map((step: any, i: number) => {
                    const isSuccess = step.payload?.status === 'success';
                    const isInitiated = step.stepType?.includes('initiated');
                    const icon = isSuccess ? 'status-positive' : isInitiated ? 'status-info' : 'status-in-progress';
                    const label = step.stepType?.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());

                    return (
                      <Container key={i} variant="stacked">
                        <SpaceBetween size="xxs" direction="horizontal">
                          <Box variant="small" color="text-body-secondary">{`Step ${i + 1}`}</Box>
                          <Box variant="small" color="text-body-secondary">{formatRelative(step.timestamp)}</Box>
                        </SpaceBetween>
                        <SpaceBetween size="xxs">
                          <Box fontWeight="bold">
                            <StatusIndicator type={isSuccess ? 'success' : isInitiated ? 'info' : 'in-progress'}>
                              {label}
                            </StatusIndicator>
                          </Box>
                          {step.userId && <Box variant="small">User: <strong>{step.userId}</strong></Box>}
                          {step.spEntityId && <Box variant="small">Application: <strong>{step.spEntityId}</strong></Box>}
                          {step.payload && Object.entries(step.payload)
                            .filter(([k]) => k !== 'status' && k !== 'tenant')
                            .map(([k, v]) => (
                              <Box key={k} variant="small" color="text-body-secondary">{k}: {String(v)}</Box>
                            ))
                          }
                        </SpaceBetween>
                      </Container>
                    );
                  })}
                </SpaceBetween>
              </SpaceBetween>
            ) : (
              <Alert type="error" header="Failed to load flow details">
                Unable to retrieve flow information.
              </Alert>
            )}
          </Modal>
        )}
      </SpaceBetween>
    </PageLayout>
  );
}
