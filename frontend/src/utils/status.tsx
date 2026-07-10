import Badge from '@cloudscape-design/components/badge';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

export function getStatusIndicator(status: string) {
  const s = status?.toLowerCase();
  if (s === 'active' || s === 'success' || s === 'healthy')
    return <StatusIndicator type="success">{status}</StatusIndicator>;
  if (s === 'pending' || s === 'draft' || s === 'pending_rotation')
    return <StatusIndicator type="pending">{status}</StatusIndicator>;
  if (s === 'disabled' || s === 'retired' || s === 'stopped')
    return <StatusIndicator type="stopped">{status}</StatusIndicator>;
  if (s === 'error' || s === 'expired' || s === 'failed')
    return <StatusIndicator type="error">{status}</StatusIndicator>;
  if (s === 'grace' || s === 'warning')
    return <StatusIndicator type="warning">{status}</StatusIndicator>;
  return <StatusIndicator type="info">{status || 'Unknown'}</StatusIndicator>;
}

export function getProtocolBadge(protocol: string) {
  const p = protocol?.toLowerCase();
  if (p === 'saml') return <Badge color="blue">SAML</Badge>;
  if (p === 'oidc') return <Badge color="green">OIDC</Badge>;
  return <Badge>{protocol}</Badge>;
}

export function getCertStatusIndicator(status: string) {
  switch (status?.toLowerCase()) {
    case 'active': return <StatusIndicator type="success">Active</StatusIndicator>;
    case 'backup': return <StatusIndicator type="info">Backup (standby)</StatusIndicator>;
    case 'pending': return <StatusIndicator type="pending">Pending activation</StatusIndicator>;
    case 'grace': return <StatusIndicator type="warning">Grace period</StatusIndicator>;
    case 'retired': return <StatusIndicator type="stopped">Retired</StatusIndicator>;
    default: return <StatusIndicator type="info">{status}</StatusIndicator>;
  }
}
