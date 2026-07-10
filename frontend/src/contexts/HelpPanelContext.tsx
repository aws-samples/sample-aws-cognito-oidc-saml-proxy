import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';

/**
 * A single contextual help topic shown in the AppLayout tools (right-side) panel.
 * `header` is rendered in the panel's header region (pass an <h2>); `content`
 * is the panel body.
 */
export interface HelpContent {
  header: ReactNode;
  content: ReactNode;
}

interface HelpPanelContextValue {
  open: boolean;
  content: HelpContent | null;
  /** Sets the help topic and opens the panel. Wire this to Info links. */
  openHelp: (content: HelpContent) => void;
  /** Controls panel visibility (wired to AppLayout onToolsChange). */
  setOpen: (open: boolean) => void;
}

const HelpPanelContext = createContext<HelpPanelContextValue | undefined>(undefined);

/**
 * Provides shared state for the contextual help panel. The app shell (App.tsx)
 * consumes this to drive AppLayout's tools/toolsOpen/onToolsChange, and any page
 * can call openHelp(...) (typically via the <InfoLink> component) to reveal a
 * topic in the right-side panel.
 */
export function HelpPanelProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [content, setContent] = useState<HelpContent | null>(null);

  const openHelp = useCallback((next: HelpContent) => {
    setContent(next);
    setOpen(true);
  }, []);

  return (
    <HelpPanelContext.Provider value={{ open, content, openHelp, setOpen }}>
      {children}
    </HelpPanelContext.Provider>
  );
}

export function useHelpPanel(): HelpPanelContextValue {
  const ctx = useContext(HelpPanelContext);
  if (!ctx) {
    throw new Error('useHelpPanel must be used within a HelpPanelProvider');
  }
  return ctx;
}
