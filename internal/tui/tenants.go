package tui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tenant"
)

type tenantsMode int

const (
	tenantsModeNormal tenantsMode = iota
	tenantsModeCreate
	tenantsModeConfirmDelete
)

type TenantsModel struct {
	client  *APIClient
	table   table.Model
	tenants []TenantInfo
	loading bool
	err     error

	mode         tenantsMode
	slugInput    textinput.Model
	nameInput    textinput.Model
	createOnName bool // focus: false = slug, true = display name
	deleteTarget string
	statusMsg    string

	// authErr is set when the failure is a missing/invalid credential
	// (ErrNoToken). In that case the tool fails closed: it shows the auth
	// error and does NOT degrade to mock data.
	authErr bool
}

func NewTenantsModel(client *APIClient) TenantsModel {
	columns := []table.Column{
		{Title: "Slug", Width: 20},
		{Title: "Display Name", Width: 30},
		{Title: "Plan", Width: 15},
		{Title: "Status", Width: 10},
		{Title: "Apps", Width: 8},
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

	slug := textinput.New()
	slug.Placeholder = "tenant-slug (lowercase, e.g. acme-corp)"
	slug.CharLimit = 63
	slug.Width = 40

	name := textinput.New()
	name.Placeholder = "Display Name"
	name.CharLimit = 255
	name.Width = 40

	return TenantsModel{
		client:    client,
		table:     t,
		loading:   true,
		mode:      tenantsModeNormal,
		slugInput: slug,
		nameInput: name,
	}
}

func (m TenantsModel) Init() tea.Cmd {
	return m.client.ListTenants()
}

// IsCapturingInput reports whether the model is in a mode that consumes all key
// input (create form or delete confirmation). The parent App checks this so its
// global keybindings (q to quit, tab to switch views) don't steal keystrokes.
func (m TenantsModel) IsCapturingInput() bool {
	return m.mode != tenantsModeNormal
}

func (m TenantsModel) Update(msg tea.Msg) (TenantsModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.table.SetHeight(msg.Height - 10)
		return m, nil

	case TenantsLoadedMsg:
		if msg.Err != nil {
			m.err = msg.Err
			m.loading = false
			if errors.Is(msg.Err, ErrNoToken) {
				// Fail closed: no credential configured. Do NOT fall back to
				// mock data — surface the auth error and show no tenants.
				m.authErr = true
				m.tenants = nil
			} else {
				m.authErr = false
				m.tenants = getMockTenants()
			}
		} else {
			m.tenants = msg.Tenants
			m.loading = false
			m.err = nil
			m.authErr = false
		}
		m.table.SetRows(m.buildRows())
		return m, nil

	case TenantMutatedMsg:
		if msg.Err != nil {
			m.statusMsg = fmt.Sprintf("✗ %s failed: %v", msg.Action, msg.Err)
		} else {
			m.statusMsg = fmt.Sprintf("✓ tenant %q %s", msg.Slug, msg.Action)
		}
		// Reload the list to reflect the change.
		return m, m.client.ListTenants()

	case tea.KeyMsg:
		switch m.mode {
		case tenantsModeCreate:
			return m.updateCreate(msg)
		case tenantsModeConfirmDelete:
			return m.updateConfirmDelete(msg)
		default:
			return m.updateNormal(msg)
		}
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m TenantsModel) updateNormal(msg tea.KeyMsg) (TenantsModel, tea.Cmd) {
	switch msg.String() {
	case "n":
		m.mode = tenantsModeCreate
		m.statusMsg = ""
		m.slugInput.SetValue("")
		m.nameInput.SetValue("")
		m.createOnName = false
		m.slugInput.Focus()
		m.nameInput.Blur()
		return m, textinput.Blink
	case "d":
		target := m.SelectedTenant()
		if target == "" {
			return m, nil
		}
		if target == tenant.DefaultSlug {
			m.statusMsg = "✗ the default tenant cannot be deleted"
			return m, nil
		}
		m.deleteTarget = target
		m.mode = tenantsModeConfirmDelete
		return m, nil
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m TenantsModel) updateCreate(msg tea.KeyMsg) (TenantsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = tenantsModeNormal
		return m, nil
	case "tab", "shift+tab":
		m.createOnName = !m.createOnName
		if m.createOnName {
			m.slugInput.Blur()
			m.nameInput.Focus()
		} else {
			m.nameInput.Blur()
			m.slugInput.Focus()
		}
		return m, textinput.Blink
	case "enter":
		slug := strings.TrimSpace(m.slugInput.Value())
		name := strings.TrimSpace(m.nameInput.Value())
		if slug == "" {
			m.statusMsg = "✗ slug is required"
			return m, nil
		}
		if name == "" {
			name = slug
		}
		m.mode = tenantsModeNormal
		return m, m.client.CreateTenant(slug, name)
	}

	var cmd tea.Cmd
	if m.createOnName {
		m.nameInput, cmd = m.nameInput.Update(msg)
	} else {
		m.slugInput, cmd = m.slugInput.Update(msg)
	}
	return m, cmd
}

func (m TenantsModel) updateConfirmDelete(msg tea.KeyMsg) (TenantsModel, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		slug := m.deleteTarget
		m.mode = tenantsModeNormal
		m.deleteTarget = ""
		return m, m.client.DeleteTenant(slug)
	case "n", "N", "esc":
		m.mode = tenantsModeNormal
		m.deleteTarget = ""
		return m, nil
	}
	return m, nil
}

func (m TenantsModel) View() string {
	if m.loading {
		return LoadingView()
	}

	switch m.mode {
	case tenantsModeCreate:
		return m.viewCreate()
	case tenantsModeConfirmDelete:
		return m.viewConfirmDelete()
	}

	var content string
	content += TitleStyle.Render("Tenants") + "\n\n"
	content += m.table.View() + "\n\n"

	help := HelpStyle.Render("↑/↓: navigate • enter: select • n: new • d: delete • tab: next view • q: quit")
	content += help

	if m.statusMsg != "" {
		content += "\n\n" + HelpStyle.Render(m.statusMsg)
	}
	if m.authErr {
		content += "\n\n" + ErrorStyle.Render(fmt.Sprintf("⛔ Not authenticated: %v", m.err))
		content += "\n" + HelpStyle.Render("(Refusing to contact the API unauthenticated. No mock data shown.)")
	} else if m.err != nil {
		content += "\n\n" + ErrorStyle.Render(fmt.Sprintf("⚠ API Unavailable: %v", m.err))
		content += "\n" + HelpStyle.Render("(Showing mock data)")
	}

	return content
}

func (m TenantsModel) viewCreate() string {
	var content string
	content += TitleStyle.Render("New Tenant") + "\n\n"
	content += "Slug\n" + m.slugInput.View() + "\n\n"
	content += "Display Name\n" + m.nameInput.View() + "\n\n"
	content += HelpStyle.Render("tab: switch field • enter: create • esc: cancel")
	if m.statusMsg != "" {
		content += "\n\n" + ErrorStyle.Render(m.statusMsg)
	}
	return content
}

func (m TenantsModel) viewConfirmDelete() string {
	var content string
	content += TitleStyle.Render("Delete Tenant") + "\n\n"
	content += fmt.Sprintf("Delete tenant %q? This cannot be undone.\n\n", m.deleteTarget)
	content += HelpStyle.Render("y: confirm • n/esc: cancel")
	return content
}

func (m TenantsModel) buildRows() []table.Row {
	rows := make([]table.Row, len(m.tenants))
	for i, t := range m.tenants {
		rows[i] = table.Row{
			t.Slug,
			t.DisplayName,
			t.Plan,
			t.Status,
			fmt.Sprintf("%d", t.AppCount),
			t.CreatedAt.Format("2006-01-02 15:04"),
		}
	}
	return rows
}

func (m TenantsModel) SelectedTenant() string {
	if len(m.tenants) == 0 {
		return ""
	}
	cursor := m.table.Cursor()
	if cursor < len(m.tenants) {
		return m.tenants[cursor].Slug
	}
	return ""
}

// Mock data for when API is unavailable
func getMockTenants() []TenantInfo {
	return []TenantInfo{
		{
			Slug:        "acme-corp",
			DisplayName: "ACME Corporation",
			Plan:        "enterprise",
			Status:      "active",
			AppCount:    5,
			CreatedAt:   mustParseTime("2024-01-15T10:30:00Z"),
		},
		{
			Slug:        "globex",
			DisplayName: "Globex Inc",
			Plan:        "business",
			Status:      "active",
			AppCount:    3,
			CreatedAt:   mustParseTime("2024-02-20T14:15:00Z"),
		},
		{
			Slug:        "stark-industries",
			DisplayName: "Stark Industries",
			Plan:        "enterprise",
			Status:      "active",
			AppCount:    8,
			CreatedAt:   mustParseTime("2024-03-10T09:00:00Z"),
		},
	}
}
