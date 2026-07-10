package tui

import (
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ApplicationsModel struct {
	client         *APIClient
	table          table.Model
	applications   []ApplicationInfo
	selectedTenant string
	loading        bool
	err            error
	// authErr is set when the failure is a missing credential (ErrNoToken);
	// the model fails closed and does NOT show mock data in that case.
	authErr bool
}

func NewApplicationsModel(client *APIClient) ApplicationsModel {
	columns := []table.Column{
		{Title: "Name", Width: 25},
		{Title: "Protocol", Width: 12},
		{Title: "Identity Source", Width: 25},
		{Title: "Status", Width: 10},
		{Title: "Created", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return ApplicationsModel{
		client:  client,
		table:   t,
		loading: false,
	}
}

func (m ApplicationsModel) Init() tea.Cmd {
	// Don't auto-load, wait for tenant selection
	return nil
}

func (m ApplicationsModel) Update(msg tea.Msg) (ApplicationsModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Adjust table height based on window size
		m.table.SetHeight(msg.Height - 10)

	case ApplicationsLoadedMsg:
		if msg.Err != nil {
			m.err = msg.Err
			m.loading = false
			if errors.Is(msg.Err, ErrNoToken) {
				// Fail closed: no credential configured. Do NOT show mock data.
				m.authErr = true
				m.applications = nil
			} else {
				m.authErr = false
				// Show mock data
				m.applications = getMockApplications()
			}
		} else {
			m.applications = msg.Applications
			m.loading = false
			m.authErr = false
		}
		m.table.SetRows(m.buildRows())

	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			// Refresh applications for current tenant
			if m.selectedTenant != "" {
				m.loading = true
				return m, m.client.ListApplications(m.selectedTenant)
			}
		}
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m ApplicationsModel) View() string {
	var content string

	// Title
	title := TitleStyle.Render("Applications")
	content += title + "\n"

	if m.selectedTenant != "" {
		subtitle := HelpStyle.Render(fmt.Sprintf("Tenant: %s", m.selectedTenant))
		content += subtitle + "\n\n"
	} else {
		content += HelpStyle.Render("No tenant selected") + "\n\n"
	}

	if m.loading {
		content += LoadingView()
		return content
	}

	// Table
	if len(m.applications) == 0 {
		content += BoxStyle.Render("No applications found")
	} else {
		content += m.table.View()
	}

	content += "\n\n"

	// Help
	help := HelpStyle.Render("↑/↓: navigate • r: refresh • tab: next view • q: quit")
	content += help

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

func (m ApplicationsModel) buildRows() []table.Row {
	rows := make([]table.Row, len(m.applications))
	for i, app := range m.applications {
		rows[i] = table.Row{
			app.Name,
			app.Protocol,
			app.IdentitySource,
			app.Status,
			app.CreatedAt.Format("2006-01-02 15:04"),
		}
	}
	return rows
}

func (m *ApplicationsModel) LoadTenant(tenant string) tea.Cmd {
	m.selectedTenant = tenant
	m.loading = true
	return m.client.ListApplications(tenant)
}

// Mock data for when API is unavailable
func getMockApplications() []ApplicationInfo {
	return []ApplicationInfo{
		{
			Name:           "Customer Portal",
			Protocol:       "SAML",
			IdentitySource: "cognito://us-east-1_ABC123",
			Status:         "active",
			CreatedAt:      mustParseTime("2024-01-20T10:00:00Z"),
		},
		{
			Name:           "Admin Dashboard",
			Protocol:       "OIDC",
			IdentitySource: "cognito://us-east-1_ABC123",
			Status:         "active",
			CreatedAt:      mustParseTime("2024-02-15T11:30:00Z"),
		},
		{
			Name:           "Mobile App",
			Protocol:       "OIDC",
			IdentitySource: "cognito://us-east-1_XYZ789",
			Status:         "active",
			CreatedAt:      mustParseTime("2024-03-01T09:15:00Z"),
		},
	}
}

// Helper function to parse time (panics on error - only for mock data)
func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
