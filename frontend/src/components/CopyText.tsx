import { Button, Popover, StatusIndicator } from '@cloudscape-design/components';
import { useState } from 'react';

interface CopyTextProps {
  text: string;
  truncate?: boolean;
}

/**
 * Resolves a displayed value to the string that should be placed on the
 * clipboard. Endpoint URLs are often rendered as relative paths (e.g.
 * "/t/demo/saml/metadata") because the management API builds them without a
 * base URL. The admin console is served from the same origin as the gateway,
 * so we expand relative paths to a fully-qualified URL on copy while leaving
 * the on-screen value relative. Already-absolute values are copied verbatim.
 */
function resolveCopyValue(text: string): string {
  if (text.startsWith('/')) {
    return `${window.location.origin}${text}`;
  }
  return text;
}

export default function CopyText({ text, truncate }: CopyTextProps) {
  const [copied, setCopied] = useState(false);

  const copyValue = resolveCopyValue(text);
  const isExpandedUrl = copyValue !== text;
  const tooltip = isExpandedUrl
    ? 'Copies the full URL to your clipboard'
    : 'Copy to clipboard';

  const handleCopy = () => {
    navigator.clipboard.writeText(copyValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }} className="copy-text">
      <code style={{
        fontSize: '13px',
        padding: '2px 6px',
        backgroundColor: '#f2f3f3',
        borderRadius: '4px',
        maxWidth: truncate ? '300px' : undefined,
        overflow: truncate ? 'hidden' : undefined,
        textOverflow: truncate ? 'ellipsis' : undefined,
        whiteSpace: 'nowrap',
      }}>
        {text}
      </code>
      <Popover
        dismissButton={false}
        position="top"
        size="small"
        triggerType="custom"
        content={<StatusIndicator type="success">Copied</StatusIndicator>}
      >
        <span title={tooltip} style={{ display: 'inline-flex' }}>
          <Button
            iconName="copy"
            variant="inline-icon"
            onClick={handleCopy}
            ariaLabel={tooltip}
          />
        </span>
      </Popover>
    </span>
  );
}
