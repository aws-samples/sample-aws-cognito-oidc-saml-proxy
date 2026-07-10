import { AppLayout, BreadcrumbGroup, Button, Box, SpaceBetween, Spinner, Header, Container, HelpPanel } from '@cloudscape-design/components';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import { Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import { Suspense, lazy, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import Navigation from './components/Navigation';
import { useAuth } from './contexts/AuthContext';
import { useHelpPanel } from './contexts/HelpPanelContext';
import { useTenants, useCreateTenant, useDeleteTenant } from './hooks/useTenants';
import { getActiveTenant, setActiveTenant, DEFAULT_TENANT_SLUG } from './tenant';

const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const ApplicationsPage = lazy(() => import('./pages/ApplicationsPage'));
const AppDetailPage = lazy(() => import('./pages/AppDetailPage'));
const RegisterAppPage = lazy(() => import('./pages/RegisterAppPage'));
const IdentitySourcesPage = lazy(() => import('./pages/IdentitySourcesPage'));
const IdentitySourceDetailPage = lazy(() => import('./pages/IdentitySourceDetailPage'));
const AnalyticsPage = lazy(() => import('./pages/AnalyticsPage'));
const AuditLogPage = lazy(() => import('./pages/AuditLogPage'));
const DebuggerPage = lazy(() => import('./pages/DebuggerPage'));
const CertificatesPage = lazy(() => import('./pages/CertificatesPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));

const BREADCRUMBS: Record<string, { text: string; href: string }[]> = {
  '/': [{ text: 'Overview', href: '/' }],
  '/identity-sources': [{ text: 'Overview', href: '/' }, { text: 'Identity Sources', href: '/identity-sources' }],
  '/applications': [{ text: 'Overview', href: '/' }, { text: 'Applications', href: '/applications' }],
  '/applications/new': [{ text: 'Overview', href: '/' }, { text: 'Applications', href: '/applications' }, { text: 'Register new', href: '/applications/new' }],
  '/analytics': [{ text: 'Overview', href: '/' }, { text: 'Analytics', href: '/analytics' }],
  '/audit': [{ text: 'Overview', href: '/' }, { text: 'Audit Log', href: '/audit' }],
  '/debugger': [{ text: 'Overview', href: '/' }, { text: 'Protocol Debugger', href: '/debugger' }],
  '/certificates': [{ text: 'Overview', href: '/' }, { text: 'Certificates', href: '/certificates' }],
  '/settings': [{ text: 'Overview', href: '/' }, { text: 'Settings', href: '/settings' }],
};

function LoginPage() {
  const { login } = useAuth();
  return (
    <Box margin={{ top: 'xxxl' }} textAlign="center">
      <Container>
        <SpaceBetween size="l">
          <Header variant="h1">Identity Federation Gateway</Header>
          <Box variant="p" color="text-body-secondary">
            Sign in with your organization credentials to manage federation settings,
            applications, and identity sources.
          </Box>
          <Button variant="primary" onClick={login}>Sign in with Cognito</Button>
        </SpaceBetween>
      </Container>
    </Box>
  );
}

export default function App() {
  const location = useLocation();
  const { isAuthenticated, isLoading, user, logout } = useAuth();
  const help = useHelpPanel();
  const queryClient = useQueryClient();
  const { data: tenants } = useTenants();
  const createTenant = useCreateTenant();
  const deleteTenant = useDeleteTenant();

  const activeTenant = getActiveTenant() ?? DEFAULT_TENANT_SLUG;

  // Handle OAuth callback — Amplify processes the code automatically.
  // Once authenticated, redirect to dashboard.
  const navigate = useNavigate();

  // Switch the configured tenant: persist the selection, drop all cached
  // query data (it belongs to the previous tenant), and return to the overview.
  const switchTenant = (slug: string) => {
    setActiveTenant(slug === DEFAULT_TENANT_SLUG ? null : slug);
    queryClient.clear();
    navigate('/');
  };

  const handleTenantMenu = async (id: string) => {
    if (id.startsWith('switch:')) {
      switchTenant(id.slice('switch:'.length));
      return;
    }
    if (id === 'create-tenant') {
      const slug = window.prompt('New tenant slug (lowercase, e.g. acme-corp):')?.trim();
      if (!slug) return;
      const displayName = window.prompt('Display name:', slug)?.trim() || slug;
      try {
        await createTenant.mutateAsync({ slug, displayName });
        switchTenant(slug);
      } catch (e) {
        window.alert(`Create tenant failed: ${e instanceof Error ? e.message : String(e)}`);
      }
      return;
    }
    if (id === 'delete-tenant') {
      if (activeTenant === DEFAULT_TENANT_SLUG) return;
      if (!window.confirm(`Delete tenant "${activeTenant}"? This cannot be undone.`)) return;
      try {
        await deleteTenant.mutateAsync(activeTenant);
        switchTenant(DEFAULT_TENANT_SLUG);
      } catch (e) {
        window.alert(`Delete tenant failed: ${e instanceof Error ? e.message : String(e)}`);
      }
      return;
    }
  };
  useEffect(() => {
    if (location.pathname === '/callback' && isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [location.pathname, isAuthenticated, navigate]);

  if (location.pathname === '/callback') {
    return (
      <Box margin={{ top: 'xxxl' }} textAlign="center">
        <Spinner size="large" />
        <Box variant="p" margin={{ top: 'm' }}>Completing sign-in...</Box>
      </Box>
    );
  }

  if (isLoading) {
    return (
      <Box margin={{ top: 'xxxl' }} textAlign="center">
        <Spinner size="large" />
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  // Handle dynamic routes
  let breadcrumbs = BREADCRUMBS[location.pathname];
  if (!breadcrumbs && location.pathname.startsWith('/identity-sources/')) {
    breadcrumbs = [
      { text: 'Overview', href: '/' },
      { text: 'Identity Sources', href: '/identity-sources' },
      { text: 'Detail', href: location.pathname },
    ];
  }
  if (!breadcrumbs && location.pathname.startsWith('/applications/') && location.pathname !== '/applications/new') {
    breadcrumbs = [
      { text: 'Overview', href: '/' },
      { text: 'Applications', href: '/applications' },
      { text: 'Detail', href: location.pathname },
    ];
  }
  breadcrumbs = breadcrumbs || [{ text: 'Overview', href: '/' }];

  return (
    <>
      <div id="top-nav">
        <TopNavigation
          identity={{
            href: '/',
            title: 'Identity Federation Gateway',
          }}
          utilities={[
            {
              type: 'menu-dropdown',
              text: `Tenant: ${activeTenant}`,
              iconName: 'multiscreen',
              ariaLabel: 'Tenant switcher',
              items: [
                {
                  id: 'switch-group',
                  text: 'Switch tenant',
                  items: (tenants ?? []).map((t) => ({
                    id: `switch:${t.slug}`,
                    text: `${t.displayName} (${t.slug})`,
                    disabled: t.slug === activeTenant,
                  })),
                },
                { id: 'create-tenant', text: 'Create tenant…' },
                {
                  id: 'delete-tenant',
                  text: `Delete "${activeTenant}"…`,
                  disabled: activeTenant === DEFAULT_TENANT_SLUG,
                },
              ],
              onItemClick: ({ detail }) => {
                void handleTenantMenu(detail.id);
              },
            },
            {
              type: 'menu-dropdown',
              text: user?.username || '',
              iconName: 'user-profile',
              items: [
                { id: 'signout', text: 'Sign out' },
              ],
              onItemClick: ({ detail }) => {
                if (detail.id === 'signout') logout();
              },
            },
          ]}
        />
      </div>
      <AppLayout
        navigation={<Navigation />}
        breadcrumbs={<BreadcrumbGroup items={breadcrumbs} />}
        headerSelector="#top-nav"
        tools={
          <HelpPanel header={help.content?.header ?? <h2>Help</h2>}>
            {help.content?.content ?? (
              <p>
                Select an <b>Info</b> link next to a section title to see configuration
                guidance here.
              </p>
            )}
          </HelpPanel>
        }
        toolsOpen={help.open}
        onToolsChange={({ detail }) => help.setOpen(detail.open)}
        content={
          <Suspense fallback={<div>Loading...</div>}>
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/identity-sources" element={<IdentitySourcesPage />} />
              <Route path="/identity-sources/:id" element={<IdentitySourceDetailPage />} />
              <Route path="/applications" element={<ApplicationsPage />} />
              <Route path="/applications/new" element={<RegisterAppPage />} />
              <Route path="/applications/:id" element={<AppDetailPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/audit" element={<AuditLogPage />} />
              <Route path="/debugger" element={<DebuggerPage />} />
              <Route path="/certificates" element={<CertificatesPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </Suspense>
        }
      />
    </>
  );
}
