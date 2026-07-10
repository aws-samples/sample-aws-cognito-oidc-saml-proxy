import {
  Table,
  Header,
  Button,
  SpaceBetween,
  PropertyFilter,
  Pagination,
  Box,
  Link,
  Spinner,
  Alert,
} from '@cloudscape-design/components';
import type { PropertyFilterProps } from '@cloudscape-design/components';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { useNavigate } from 'react-router-dom';
import { useApplications } from '../hooks/useApplications';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { applicationsPageHelp } from '../help/miscHelp';
import { getProtocolBadge, getStatusIndicator } from '../utils/status';
import { formatDate } from '../utils/format';

const FILTER_PROPERTIES: PropertyFilterProps.FilteringProperty[] = [
  {
    key: 'protocol',
    operators: ['='],
    propertyLabel: 'Protocol',
    groupValuesLabel: 'Protocol values',
  },
  {
    key: 'status',
    operators: ['='],
    propertyLabel: 'Status',
    groupValuesLabel: 'Status values',
  },
];

export default function ApplicationsPage() {
  const navigate = useNavigate();
  const { data: applications = [], isLoading, isError, error, refetch } = useApplications();

  const { items, collectionProps, propertyFilterProps, paginationProps } =
    useCollection(applications, {
      propertyFiltering: {
        filteringProperties: FILTER_PROPERTIES,
        empty: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No applications</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No applications to display.
            </Box>
          </Box>
        ),
        noMatch: (
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No matches</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              No applications match the filter criteria.
            </Box>
          </Box>
        ),
      },
      pagination: { pageSize: 10 },
      sorting: {},
    });

  if (isError) {
    return (
      <PageLayout
        title="Applications"
        description="Manage federated SAML and OIDC applications"
      >
        <Alert
          type="error"
          header="Unable to load applications"
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
        title="Applications"
        description="Manage federated SAML and OIDC applications"
      >
        <Box textAlign="center" padding="l">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  return (
    <PageLayout
      title="Applications"
      description="Manage federated SAML and OIDC applications"
      info={<InfoLink content={applicationsPageHelp} ariaLabel="Info about applications" />}
      actions={
        <Button variant="primary" onClick={() => navigate('/applications/new')}>
          Register application
        </Button>
      }
    >
      <Table
        {...collectionProps}
        variant="borderless"
        loading={isLoading}
        columnDefinitions={[
          {
            id: 'displayName',
            header: 'Name',
            cell: (item) => (
              <Link href={`/applications/${item.id}`}>{item.displayName}</Link>
            ),
            sortingField: 'displayName',
            isRowHeader: true,
            width: 280,
            minWidth: 200,
          },
          {
            id: 'protocol',
            header: 'Protocol',
            cell: (item) => getProtocolBadge(item.protocol),
            sortingField: 'protocol',
            width: 120,
            minWidth: 100,
          },
          {
            id: 'sourceId',
            header: 'Identity Source',
            cell: (item) => {
              if (item.sourceId) {
                return item.sourceId.length > 8
                  ? `${item.sourceId.substring(0, 8)}...`
                  : item.sourceId;
              }
              return 'Not assigned';
            },
            sortingField: 'sourceId',
            width: 200,
            minWidth: 150,
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
        ]}
        items={items}
        empty={
          <Box textAlign="center" color="inherit">
            <Box variant="p" color="inherit">
              <b>No applications</b>
            </Box>
            <Box variant="p" color="inherit" padding={{ bottom: 's' }}>
              You have not registered any applications yet.
            </Box>
            <Button onClick={() => navigate('/applications/new')}>
              Register application
            </Button>
          </Box>
        }
        filter={
          <PropertyFilter
            {...propertyFilterProps}
            i18nStrings={{
              filteringAriaLabel: 'Filter applications',
              dismissAriaLabel: 'Dismiss',
              filteringPlaceholder: 'Filter applications by property',
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
          <Header counter={`(${applications.length})`}>Applications</Header>
        }
        pagination={<Pagination {...paginationProps} />}
      />
    </PageLayout>
  );
}
