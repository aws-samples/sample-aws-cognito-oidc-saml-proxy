import { SideNavigation, SideNavigationProps } from '@cloudscape-design/components';
import { useNavigate, useLocation } from 'react-router-dom';

const NAV_ITEMS: SideNavigationProps.Item[] = [
  { type: 'link', text: 'Overview', href: '/' },
  { type: 'divider' },
  {
    type: 'section',
    text: 'Identity Sources',
    items: [
      { type: 'link', text: 'All sources', href: '/identity-sources' },
    ],
  },
  {
    type: 'section',
    text: 'Applications',
    items: [
      { type: 'link', text: 'All applications', href: '/applications' },
      { type: 'link', text: 'Register new', href: '/applications/new' },
    ],
  },
  { type: 'divider' },
  {
    type: 'section',
    text: 'Monitoring',
    items: [
      { type: 'link', text: 'Analytics', href: '/analytics' },
      { type: 'link', text: 'Audit log', href: '/audit' },
    ],
  },
  {
    type: 'section',
    text: 'Tools',
    items: [
      { type: 'link', text: 'Protocol debugger', href: '/debugger' },
      { type: 'link', text: 'Certificates', href: '/certificates' },
    ],
  },
  { type: 'divider' },
  {
    type: 'section',
    text: 'Settings',
    items: [
      { type: 'link', text: 'Gateway configuration', href: '/settings' },
    ],
  },
];

export default function Navigation() {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <SideNavigation
      activeHref={location.pathname}
      header={{ text: 'Federation Gateway', href: '/' }}
      items={NAV_ITEMS}
      onFollow={(event) => {
        if (!event.detail.external) {
          event.preventDefault();
          navigate(event.detail.href);
        }
      }}
    />
  );
}
