import {
  Container,
  Header,
  SpaceBetween,
  KeyValuePairs,
  ProgressBar,
  Button,
  Spinner,
  Alert,
  Table,
  Box,
  Modal,
  FormField,
  Textarea,
  Badge,
} from '@cloudscape-design/components';
import { useState } from 'react';
import PageLayout from '../components/PageLayout';
import InfoLink from '../components/InfoLink';
import { activeCertHelp, backupCertHelp, allCertsHelp } from '../help/certificatesHelp';
import CopyText from '../components/CopyText';
import { getCertStatusIndicator } from '../utils/status';
import { formatDate } from '../utils/format';
import {
  useCertificates,
  useGenerateCSR,
  useImportCertificate,
  usePromoteBackup,
  type CertEntry,
  type CertRole,
} from '../hooks/useCertificates';

function downloadCert(cert: CertEntry) {
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.pemBase64}\n-----END CERTIFICATE-----\n`;
  downloadBlob(pem, `certificate-${cert.role}-${cert.id}.pem`, 'application/x-pem-file');
}

function downloadBlob(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function sourceBadge(source: CertEntry['source']) {
  return source === 'ca-issued' ? (
    <Badge color="blue">CA-issued</Badge>
  ) : (
    <Badge color="grey">Self-signed</Badge>
  );
}

function certItems(cert: CertEntry) {
  const totalDays = (() => {
    try {
      const start = new Date(cert.notBefore).getTime();
      const end = new Date(cert.notAfter).getTime();
      return Math.max(1, Math.round((end - start) / (1000 * 60 * 60 * 24)));
    } catch {
      return 365;
    }
  })();
  const remaining = Math.max(0, cert.daysRemaining);
  const progressValue = Math.round((remaining / totalDays) * 100);

  return [
    { label: 'Subject', value: cert.subject || '\u2014' },
    { label: 'Issuer', value: cert.issuer || '\u2014' },
    { label: 'Source', value: sourceBadge(cert.source) },
    { label: 'Signing key', value: cert.kmsKeyId ? <CopyText text={cert.kmsKeyId} truncate /> : 'Primary' },
    { label: 'Valid From', value: formatDate(cert.notBefore) },
    { label: 'Valid Until', value: formatDate(cert.notAfter) },
    { label: 'Fingerprint', value: <CopyText text={cert.fingerprint} truncate /> },
    { label: 'Status', value: getCertStatusIndicator(cert.status) },
    {
      label: 'Expiry',
      value: (
        <ProgressBar
          variant="key-value"
          value={progressValue}
          label={`${cert.daysRemaining} days remaining`}
          status={cert.daysRemaining < 30 ? 'error' : 'in-progress'}
        />
      ),
    },
  ];
}

export default function CertificatesPage() {
  const { data: certificates, isLoading, isError, error, refetch } = useCertificates();
  const generateCSR = useGenerateCSR();
  const importCert = useImportCertificate();
  const promoteBackup = usePromoteBackup();

  const [importRole, setImportRole] = useState<CertRole | null>(null);
  const [importPem, setImportPem] = useState('');
  const [promoteVisible, setPromoteVisible] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleGenerateCSR = async (role: CertRole) => {
    setBanner(null);
    try {
      const { csrPem } = await generateCSR.mutateAsync(role);
      downloadBlob(csrPem, `signing-csr-${role}.pem`, 'application/pkcs10');
      setBanner({
        type: 'success',
        text: `CSR for the ${role} key downloaded. Have your corporate CA sign it, then import the issued certificate.`,
      });
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to generate CSR' });
    }
  };

  const openImport = (role: CertRole) => {
    setImportRole(role);
    setImportPem('');
  };

  const handleImport = async () => {
    if (!importRole) return;
    setBanner(null);
    try {
      await importCert.mutateAsync({ role: importRole, certPem: importPem });
      setBanner({ type: 'success', text: `Imported ${importRole} certificate successfully.` });
      setImportRole(null);
      setImportPem('');
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to import certificate' });
    }
  };

  const handlePromote = async () => {
    setBanner(null);
    try {
      await promoteBackup.mutateAsync();
      setBanner({ type: 'success', text: 'Backup certificate promoted to active.' });
      setPromoteVisible(false);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to promote backup' });
      setPromoteVisible(false);
    }
  };

  if (isLoading) {
    return (
      <PageLayout title="Certificates" description="Signing certificate lifecycle and external CA import">
        <Box textAlign="center" padding="l">
          <Spinner size="large" />
        </Box>
      </PageLayout>
    );
  }

  if (isError) {
    return (
      <PageLayout title="Certificates" description="Signing certificate lifecycle and external CA import">
        <Alert
          type="error"
          header="Unable to load certificate information"
          action={<Button onClick={() => refetch()}>Retry</Button>}
        >
          {error instanceof Error ? error.message : 'An error occurred while fetching certificate information.'}
        </Alert>
      </PageLayout>
    );
  }

  if (!certificates || certificates.length === 0) {
    return (
      <PageLayout title="Certificates" description="Signing certificate lifecycle and external CA import">
        <Alert type="info">
          Certificate information will be available after the gateway processes its first request.
        </Alert>
      </PageLayout>
    );
  }

  const activeCert = certificates.find((c) => c.role === 'active');
  const backupCert = certificates.find((c) => c.role === 'backup');

  return (
    <PageLayout title="Certificates" description="Signing certificate lifecycle and external CA import">
      <SpaceBetween size="l">
        {banner && (
          <Alert type={banner.type} dismissible onDismiss={() => setBanner(null)}>
            {banner.text}
          </Alert>
        )}

        {/* Active certificate */}
        {activeCert ? (
          <Container
            header={
              <Header
                variant="h2"
                info={<InfoLink content={activeCertHelp} ariaLabel="Info about the active signing certificate" />}
                actions={
                  <SpaceBetween size="xs" direction="horizontal">
                    <Button iconName="download" onClick={() => downloadCert(activeCert)}>
                      Download
                    </Button>
                    <Button
                      iconName="file"
                      loading={generateCSR.isPending}
                      onClick={() => handleGenerateCSR('active')}
                    >
                      Generate CSR
                    </Button>
                    <Button iconName="upload" onClick={() => openImport('active')}>
                      Import signed certificate
                    </Button>
                  </SpaceBetween>
                }
              >
                Active Signing Certificate
              </Header>
            }
          >
            <KeyValuePairs columns={3} items={certItems(activeCert)} />
          </Container>
        ) : (
          <Alert type="warning">No active signing certificate found.</Alert>
        )}

        {/* Backup certificate */}
        <Container
          header={
            <Header
              variant="h2"
              info={<InfoLink content={backupCertHelp} ariaLabel="Info about the backup signing certificate" />}
              description="A standby certificate published in SAML metadata so relying parties trust it ahead of a rollover. Promote it to roll over instantly on expiry or key change."
              actions={
                <SpaceBetween size="xs" direction="horizontal">
                  {backupCert && (
                    <Button iconName="download" onClick={() => downloadCert(backupCert)}>
                      Download
                    </Button>
                  )}
                  <Button
                    iconName="file"
                    loading={generateCSR.isPending}
                    onClick={() => handleGenerateCSR('backup')}
                  >
                    Generate CSR
                  </Button>
                  <Button iconName="upload" onClick={() => openImport('backup')}>
                    Import signed certificate
                  </Button>
                  <Button
                    variant="primary"
                    iconName="angle-up"
                    disabled={!backupCert}
                    onClick={() => setPromoteVisible(true)}
                  >
                    Promote to active
                  </Button>
                </SpaceBetween>
              }
            >
              Backup Signing Certificate
            </Header>
          }
        >
          {backupCert ? (
            <KeyValuePairs columns={3} items={certItems(backupCert)} />
          ) : (
            <Alert type="info">
              No backup certificate configured. Generate a CSR for the backup key, have your CA sign it,
              then import it here to enable instant rollover.
            </Alert>
          )}
        </Container>

        <Table
          header={<Header variant="h2" counter={`(${certificates.length})`} info={<InfoLink content={allCertsHelp} ariaLabel="Info about all certificates" />}>All certificates</Header>}
          columnDefinitions={[
            { id: 'role', header: 'Role', cell: (item) => getCertStatusIndicator(item.status), width: 180 },
            { id: 'source', header: 'Source', cell: (item) => sourceBadge(item.source), width: 130 },
            { id: 'subject', header: 'Subject', cell: (item) => item.subject || '\u2014' },
            { id: 'fingerprint', header: 'Fingerprint', cell: (item) => <CopyText text={item.fingerprint} truncate /> },
            { id: 'notAfter', header: 'Valid Until', cell: (item) => formatDate(item.notAfter) },
            {
              id: 'daysRemaining',
              header: 'Days Remaining',
              cell: (item) => (item.isExpired ? 'Expired' : String(item.daysRemaining)),
            },
            {
              id: 'actions',
              header: 'Actions',
              cell: (item) => (
                <Button
                  iconName="download"
                  variant="inline-icon"
                  onClick={() => downloadCert(item)}
                  ariaLabel="Download certificate"
                />
              ),
              width: 80,
            },
          ]}
          items={certificates}
          variant="container"
          empty={<Box textAlign="center" padding="l">No certificates.</Box>}
        />
      </SpaceBetween>

      {/* Import modal */}
      <Modal
        visible={importRole !== null}
        onDismiss={() => setImportRole(null)}
        header={`Import ${importRole ?? ''} certificate`}
        footer={
          <Box float="right">
            <SpaceBetween size="xs" direction="horizontal">
              <Button variant="link" onClick={() => setImportRole(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={importCert.isPending}
                disabled={importPem.trim() === ''}
                onClick={handleImport}
              >
                Import
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Paste the PEM certificate issued by your corporate CA for the {importRole} signing key. The
            leaf must be first; its public key must match the KMS key (the CA signs the CSR generated here).
          </Box>
          <FormField label="Certificate (PEM)">
            <Textarea
              value={importPem}
              onChange={(e) => setImportPem(e.detail.value)}
              placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
              rows={12}
            />
          </FormField>
        </SpaceBetween>
      </Modal>

      {/* Promote confirmation */}
      <Modal
        visible={promoteVisible}
        onDismiss={() => setPromoteVisible(false)}
        header="Promote backup certificate"
        footer={
          <Box float="right">
            <SpaceBetween size="xs" direction="horizontal">
              <Button variant="link" onClick={() => setPromoteVisible(false)}>
                Cancel
              </Button>
              <Button variant="primary" loading={promoteBackup.isPending} onClick={handlePromote}>
                Promote
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <Box variant="p">
          The backup certificate will become the active signing certificate and the backup slot will be
          cleared. Relying parties already trust the backup because it is published in SAML metadata.
        </Box>
      </Modal>
    </PageLayout>
  );
}
