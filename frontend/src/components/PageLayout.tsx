import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';

interface PageLayoutProps {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  /** Optional Info link rendered next to the page title (opens the help panel). */
  info?: React.ReactNode;
  children: React.ReactNode;
}

export default function PageLayout({ title, description, actions, info, children }: PageLayoutProps) {
  return (
    <ContentLayout
      header={
        <Header variant="h1" description={description} actions={actions} info={info}>
          {title}
        </Header>
      }
    >
      {children}
    </ContentLayout>
  );
}
