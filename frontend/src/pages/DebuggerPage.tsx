import { authFetch } from '../auth';
import {
  SpaceBetween,
  Container,
  Tabs,
  FormField,
  Textarea,
  Button,
  Input,
  Box,
  Steps,
  Alert,
  Spinner,
} from '@cloudscape-design/components';
import { useState } from 'react';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { debuggerPageHelp } from '../help/miscHelp';

const CODE_BLOCK_STYLE: React.CSSProperties = {
  padding: '16px',
  backgroundColor: '#f2f3f3',
  borderRadius: '8px',
  overflow: 'auto',
  fontSize: '13px',
  lineHeight: '1.5',
  maxHeight: '500px',
  fontFamily: 'Monaco, Menlo, Consolas, "Courier New", monospace',
  border: '1px solid #e9ebed',
};

export default function DebuggerPage() {
  const [samlInput, setSamlInput] = useState('');
  const [decodedSaml, setDecodedSaml] = useState('');
  const [decodeError, setDecodeError] = useState('');
  const [decodeLoading, setDecodeLoading] = useState(false);
  const [flowIdInput, setFlowIdInput] = useState('');
  const [flowTrace, setFlowTrace] = useState<{
    flowId: string;
    steps: Array<{
      title: string;
      description: string;
      timestamp: string;
      status: string;
    }>;
  } | null>(null);
  const [flowLoading, setFlowLoading] = useState(false);
  const [flowError, setFlowError] = useState('');

  const handleDecodeSaml = async () => {
    setDecodeError('');
    setDecodedSaml('');

    if (!samlInput.trim()) {
      setDecodeError('Please enter a base64-encoded SAML assertion');
      return;
    }

    setDecodeLoading(true);

    try {
      const res = await authFetch('/api/v1/debug/decode-assertion', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assertion: samlInput.trim() }),
      });
      if (!res.ok) throw new Error('API unavailable');
      const data = await res.json();
      setDecodedSaml(data.decoded ?? data.xml ?? JSON.stringify(data, null, 2));
    } catch {
      try {
        const decoded = atob(samlInput.trim());
        setDecodedSaml(decoded);
      } catch {
        setDecodeError('Invalid base64 encoding. Please verify your input.');
      }
    } finally {
      setDecodeLoading(false);
    }
  };

  const handleLookupFlow = async () => {
    if (!flowIdInput.trim()) {
      return;
    }

    setFlowLoading(true);
    setFlowError('');
    setFlowTrace(null);

    try {
      const res = await authFetch(`/api/v1/debug/audit-log/${flowIdInput.trim()}`);
      if (!res.ok) throw new Error('API unavailable');
      const data = await res.json();
      setFlowTrace(data);
    } catch {
      setFlowError('Failed to look up flow. Verify the flow ID and try again.');
    } finally {
      setFlowLoading(false);
    }
  };

  return (
    <PageLayout
      title="Protocol Debugger"
      description="Decode assertions and trace authentication flows"
      info={<InfoLink content={debuggerPageHelp} ariaLabel="Info about the protocol debugger" />}
    >
      <Tabs
        tabs={[
          {
            id: 'decode-assertion',
            label: 'Decode Assertion',
            content: (
              <Container>
                <SpaceBetween size="l">
                  <FormField
                    label="Base64-Encoded SAML Assertion"
                    description="Paste a base64-encoded SAML assertion to decode and view its contents"
                  >
                    <Textarea
                      value={samlInput}
                      onChange={(event) => setSamlInput(event.detail.value)}
                      placeholder="PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0Yzp..."
                      rows={6}
                    />
                  </FormField>

                  <Button
                    variant="primary"
                    onClick={handleDecodeSaml}
                    loading={decodeLoading}
                  >
                    Decode
                  </Button>

                  {decodeError && (
                    <Alert type="error" header="Decode Failed">
                      {decodeError}
                    </Alert>
                  )}

                  {decodedSaml && (
                    <FormField label="Decoded XML">
                      <Box>
                        <pre style={CODE_BLOCK_STYLE}>
                          <code>{decodedSaml}</code>
                        </pre>
                      </Box>
                    </FormField>
                  )}
                </SpaceBetween>
              </Container>
            ),
          },
          {
            id: 'flow-trace',
            label: 'Flow Trace',
            content: (
              <Container>
                <SpaceBetween size="l">
                  <FormField
                    label="Flow ID"
                    description="Enter a flow ID to view its authentication trace"
                  >
                    <Input
                      value={flowIdInput}
                      onChange={(event) => setFlowIdInput(event.detail.value)}
                      placeholder="flow-abc123"
                    />
                  </FormField>

                  <Button
                    variant="primary"
                    onClick={handleLookupFlow}
                    loading={flowLoading}
                  >
                    Lookup
                  </Button>

                  {flowError && (
                    <Alert type="error" header="Lookup Failed">
                      {flowError}
                    </Alert>
                  )}

                  {flowLoading && (
                    <Box textAlign="center" padding="l">
                      <Spinner size="large" />
                    </Box>
                  )}

                  {flowTrace && (
                    <Box>
                      <Box variant="h3" padding={{ bottom: 's' }}>
                        Flow: {flowTrace.flowId}
                      </Box>
                      <Steps
                        steps={flowTrace.steps.map(
                          (step) => ({
                            status: step.status === 'success' ? 'success' as const
                              : step.status === 'error' ? 'error' as const
                              : 'in-progress' as const,
                            header: step.title,
                            details: (
                              <SpaceBetween size="xs">
                                <Box>{step.description}</Box>
                                <Box fontSize="body-s" color="text-body-secondary">
                                  {new Date(step.timestamp).toLocaleString('en-US', {
                                    year: 'numeric',
                                    month: 'short',
                                    day: 'numeric',
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit',
                                    fractionalSecondDigits: 3,
                                  })}
                                </Box>
                              </SpaceBetween>
                            ),
                          })
                        )}
                      />
                    </Box>
                  )}
                </SpaceBetween>
              </Container>
            ),
          },
        ]}
      />
    </PageLayout>
  );
}
