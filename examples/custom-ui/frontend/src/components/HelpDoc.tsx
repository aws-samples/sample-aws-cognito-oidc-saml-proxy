import { type ReactNode } from 'react';

interface HelpDocProps {
  title?: string;
  children: ReactNode;
  defaultOpen?: boolean;
}

/**
 * Collapsible educational panel. Each page uses one to explain the URL
 * parameters, Cognito API calls, and the end-to-end flow for that operation.
 */
export default function HelpDoc({ title = 'How this works', children, defaultOpen }: HelpDocProps) {
  return (
    <details className="help" open={defaultOpen}>
      <summary>{title}</summary>
      <div className="help-body">{children}</div>
    </details>
  );
}
