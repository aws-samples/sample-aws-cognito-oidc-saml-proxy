package tui

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type DashboardModel struct {
	client  *APIClient
	stats   dashboardStats
	health  HealthInfo
	loading bool
	err     error
	// authErr is set when the failure is a missing credential (ErrNoToken);
	// the dashboard fails closed and labels the state as unauthenticated
	// rather than "offline mock data".
	authErr bool
	width   int
	height  int
}

type dashboardStats struct {
	Tenants      int
	Applications int
	Auth24h      int
	Endpoints    string
}

func NewDashboardModel(client *APIClient) DashboardModel {
	return DashboardModel{
		client:  client,
		loading: true,
		stats: dashboardStats{
			Tenants:      0,
			Applications: 0,
			Auth24h:      0,
			Endpoints:    "2",
		},
	}
}

func (m DashboardModel) Init() tea.Cmd {
	return tea.Batch(
		m.client.GetHealth(),
		m.client.ListTenants(),
	)
}

func (m DashboardModel) Update(msg tea.Msg) (DashboardModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case HealthLoadedMsg:
		if msg.Err != nil {
			m.err = msg.Err
			m.loading = false
			m.authErr = errors.Is(msg.Err, ErrNoToken)
			// Set default values for offline mode
			m.health = HealthInfo{
				Status:    "offline",
				Timestamp: "",
				SAMLOk:    false,
				OIDCOk:    false,
			}
		} else {
			m.health = msg.Health
			m.loading = false
			m.authErr = false
		}

	case TenantsLoadedMsg:
		if msg.Err != nil {
			m.err = msg.Err
			if errors.Is(msg.Err, ErrNoToken) {
				m.authErr = true
			}
		} else {
			m.stats.Tenants = len(msg.Tenants)
			// Calculate total applications
			totalApps := 0
			for _, t := range msg.Tenants {
				totalApps += t.AppCount
			}
			m.stats.Applications = totalApps
		}
	}

	return m, nil
}

func (m DashboardModel) View() string {
	if m.loading {
		return LoadingView()
	}

	var content string

	// Title
	title := TitleStyle.Render("Identity Federation Gateway - Dashboard")
	content += title + "\n\n"

	// Stats boxes
	statsRow := lipgloss.JoinHorizontal(
		lipgloss.Top,
		m.renderStatBox("Tenants", fmt.Sprintf("%d", m.stats.Tenants)),
		m.renderStatBox("Applications", fmt.Sprintf("%d", m.stats.Applications)),
		m.renderStatBox("Auth (24h)", fmt.Sprintf("%d", m.stats.Auth24h)),
		m.renderStatBox("Endpoints", m.stats.Endpoints),
	)
	content += statsRow + "\n\n"

	// Status section
	content += m.renderStatus()

	// Error display: fail closed on missing credential, otherwise offline mock.
	if m.authErr {
		content += "\n\n" + ErrorStyle.Render(fmt.Sprintf("⛔ Not authenticated: %v", m.err))
		content += "\n" + HelpStyle.Render("(Refusing to contact the API unauthenticated. No mock data shown.)")
	} else if m.err != nil {
		content += "\n\n" + ErrorStyle.Render(fmt.Sprintf("⚠ API Unavailable: %v", m.err))
		content += "\n" + HelpStyle.Render("(Showing mock data)")
	}

	return content
}

func (m DashboardModel) renderStatBox(label, value string) string {
	labelLine := StatLabelStyle.Render(label)
	valueLine := StatValueStyle.Render(value)

	box := lipgloss.JoinVertical(
		lipgloss.Left,
		labelLine,
		valueLine,
	)

	return StatBoxStyle.Render(box)
}

func (m DashboardModel) renderStatus() string {
	var content string

	content += lipgloss.NewStyle().Bold(true).Render("Endpoint Status") + "\n\n"

	// SAML endpoint
	samlStatus := StatusError.Render("✗ DOWN")
	if m.health.SAMLOk {
		samlStatus = StatusOK.Render("✓ UP")
	}
	content += fmt.Sprintf("  SAML  %s\n", samlStatus)

	// OIDC endpoint
	oidcStatus := StatusError.Render("✗ DOWN")
	if m.health.OIDCOk {
		oidcStatus = StatusOK.Render("✓ UP")
	}
	content += fmt.Sprintf("  OIDC  %s\n", oidcStatus)

	return BoxStyle.Render(content)
}

func LoadingView() string {
	return BoxStyle.Render("Loading...")
}
