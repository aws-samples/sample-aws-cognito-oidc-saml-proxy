import Link from '@cloudscape-design/components/link';
import { useHelpPanel, type HelpContent } from '../contexts/HelpPanelContext';

interface InfoLinkProps {
  /** The help topic to reveal in the right-side panel when clicked. */
  content: HelpContent;
  /** Accessible label, e.g. "Info about claim mappings". */
  ariaLabel?: string;
}

/**
 * The standard Cloudscape "Info" link. Place it in a Header's `info` slot:
 *   <Header info={<InfoLink content={claimMappingsHelp} />}>Claim Mappings</Header>
 * Clicking it opens the shared help panel with the given content.
 */
export default function InfoLink({ content, ariaLabel }: InfoLinkProps) {
  const { openHelp } = useHelpPanel();
  return (
    <Link variant="info" ariaLabel={ariaLabel} onFollow={() => openHelp(content)}>
      Info
    </Link>
  );
}
