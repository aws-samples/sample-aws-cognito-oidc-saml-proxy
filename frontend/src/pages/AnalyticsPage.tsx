import {
  SpaceBetween,
  Container,
  Box,
  Spinner,
  Alert,
  Button,
  KeyValuePairs,
  Link,
  DateRangePicker,
} from '@cloudscape-design/components';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAnalyticsOverview } from '../hooks/useAnalytics';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { analyticsPageHelp } from '../help/miscHelp';

export default function AnalyticsPage() {
  const navigate = useNavigate();
  const [dateRange] = useState({
    type: 'relative' as const,
    amount: 7,
    unit: 'day' as const,
  });

  const { data, isLoading, error, refetch } = useAnalyticsOverview();

  if (isLoading) {
    return (
      <PageLayout title="Analytics" description="Authentication metrics and trends">
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (error) {
    return (
      <PageLayout title="Analytics" description="Authentication metrics and trends">
        <Alert
          type="error"
          header="Failed to load analytics data"
          action={<Button onClick={() => refetch()}>Retry</Button>}
        >
          {error instanceof Error ? error.message : 'An unexpected error occurred'}
        </Alert>
      </PageLayout>
    );
  }

  const isEmpty = data && data.totalAuths === 0;

  return (
    <PageLayout
      title="Analytics"
      description="Authentication metrics and trends"
      info={<InfoLink content={analyticsPageHelp} ariaLabel="Info about analytics" />}
      actions={
        <DateRangePicker
          value={dateRange}
          relativeOptions={[
            { key: 'previous-7-days', amount: 7, unit: 'day', type: 'relative' },
            { key: 'previous-30-days', amount: 30, unit: 'day', type: 'relative' },
            { key: 'previous-90-days', amount: 90, unit: 'day', type: 'relative' },
          ]}
          isValidRange={() => ({ valid: true })}
          i18nStrings={{
            todayAriaLabel: 'Today',
            nextMonthAriaLabel: 'Next month',
            previousMonthAriaLabel: 'Previous month',
            customRelativeRangeDurationLabel: 'Duration',
            customRelativeRangeDurationPlaceholder: 'Enter duration',
            customRelativeRangeOptionLabel: 'Custom range',
            customRelativeRangeOptionDescription: 'Set a custom range',
            customRelativeRangeUnitLabel: 'Unit',
            formatRelativeRange: (e) =>
              `Last ${e.amount} ${e.unit}${e.amount === 1 ? '' : 's'}`,
            formatUnit: (unit, amount) => (amount === 1 ? unit : `${unit}s`),
            dateTimeConstraintText: 'Date must be in the past',
            relativeModeTitle: 'Relative range',
            absoluteModeTitle: 'Absolute range',
            relativeRangeSelectionHeading: 'Choose a range',
            startDateLabel: 'Start date',
            endDateLabel: 'End date',
            startTimeLabel: 'Start time',
            endTimeLabel: 'End time',
            clearButtonLabel: 'Clear',
            cancelButtonLabel: 'Cancel',
            applyButtonLabel: 'Apply',
          }}
          placeholder="Filter by date"
          onChange={() => {}}
        />
      }
    >
      <SpaceBetween size="l">
        {isEmpty ? (
          <Alert type="info">
            No analytics data available yet.
          </Alert>
        ) : (
          <>
            <Container>
              <KeyValuePairs
                columns={2}
                items={[
                  {
                    type: 'group',
                    items: [
                      {
                        label: 'Total Applications',
                        value: (
                          <Link
                            variant="awsui-value-large"
                            href="/applications"
                            onFollow={(e) => {
                              e.preventDefault();
                              navigate('/applications');
                            }}
                          >
                            {data?.totalSPs.toLocaleString() ?? '0'}
                          </Link>
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
                          <Link
                            variant="awsui-value-large"
                            href="/audit"
                            onFollow={(e) => {
                              e.preventDefault();
                              navigate('/audit');
                            }}
                          >
                            {data?.totalAuths.toLocaleString() ?? '0'}
                          </Link>
                        ),
                      },
                    ],
                  },
                ]}
              />
            </Container>

            <Alert type="info">
              Detailed charts and per-application metrics will be available once
              time-series analytics are implemented.
            </Alert>
          </>
        )}
      </SpaceBetween>
    </PageLayout>
  );
}
