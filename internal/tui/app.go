package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type viewType int

const (
	dashboardView viewType = iota
	tenantsView
	applicationsView
	decoderView
)

type App struct {
	client       *APIClient
	currentView  viewType
	dashboard    DashboardModel
	tenants      TenantsModel
	applications ApplicationsModel
	decoder      DecoderModel
	width        int
	height       int
}

func NewApp(client *APIClient) *App {
	return &App{
		client:       client,
		currentView:  dashboardView,
		dashboard:    NewDashboardModel(client),
		tenants:      NewTenantsModel(client),
		applications: NewApplicationsModel(client),
		decoder:      NewDecoderModel(client),
	}
}

func (a *App) Init() tea.Cmd {
	return tea.Batch(
		a.dashboard.Init(),
		a.tenants.Init(),
		a.decoder.Init(),
	)
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		// Propagate to all views
		a.dashboard, cmd = a.dashboard.Update(msg)
		cmds = append(cmds, cmd)
		a.tenants, cmd = a.tenants.Update(msg)
		cmds = append(cmds, cmd)
		a.applications, cmd = a.applications.Update(msg)
		cmds = append(cmds, cmd)
		a.decoder, cmd = a.decoder.Update(msg)
		cmds = append(cmds, cmd)

	case tea.KeyMsg:
		// When the tenants view is capturing text input (create form / delete
		// confirmation), route every key to it so the global q/tab bindings
		// don't steal keystrokes.
		if a.currentView == tenantsView && a.tenants.IsCapturingInput() {
			a.tenants, cmd = a.tenants.Update(msg)
			cmds = append(cmds, cmd)
			return a, tea.Batch(cmds...)
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return a, tea.Quit

		case "tab":
			// Cycle through views
			a.currentView = (a.currentView + 1) % 4

			// When switching to applications view, load data for selected tenant
			if a.currentView == applicationsView {
				selectedTenant := a.tenants.SelectedTenant()
				if selectedTenant != "" {
					cmd := a.applications.LoadTenant(selectedTenant)
					cmds = append(cmds, cmd)
				}
			}

		default:
			// Delegate to current view
			switch a.currentView {
			case dashboardView:
				a.dashboard, cmd = a.dashboard.Update(msg)
				cmds = append(cmds, cmd)
			case tenantsView:
				a.tenants, cmd = a.tenants.Update(msg)
				cmds = append(cmds, cmd)
			case applicationsView:
				a.applications, cmd = a.applications.Update(msg)
				cmds = append(cmds, cmd)
			case decoderView:
				a.decoder, cmd = a.decoder.Update(msg)
				cmds = append(cmds, cmd)
			}
		}

	default:
		// Propagate other messages to current view
		switch a.currentView {
		case dashboardView:
			a.dashboard, cmd = a.dashboard.Update(msg)
			cmds = append(cmds, cmd)
		case tenantsView:
			a.tenants, cmd = a.tenants.Update(msg)
			cmds = append(cmds, cmd)
		case applicationsView:
			a.applications, cmd = a.applications.Update(msg)
			cmds = append(cmds, cmd)
		case decoderView:
			a.decoder, cmd = a.decoder.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return a, tea.Batch(cmds...)
}

func (a *App) View() string {
	// Header with tabs
	header := a.renderTabs()

	// Current view content
	var content string
	switch a.currentView {
	case dashboardView:
		content = a.dashboard.View()
	case tenantsView:
		content = a.tenants.View()
	case applicationsView:
		content = a.applications.View()
	case decoderView:
		content = a.decoder.View()
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, "\n", content)
}

func (a *App) renderTabs() string {
	tabs := []struct {
		name string
		view viewType
		icon string
	}{
		{"Dashboard", dashboardView, "📊"},
		{"Tenants", tenantsView, "🏢"},
		{"Applications", applicationsView, "📱"},
		{"Decoder", decoderView, "🔍"},
	}

	var renderedTabs []string
	for _, tab := range tabs {
		style := InactiveTab
		if tab.view == a.currentView {
			style = ActiveTab
		}
		label := fmt.Sprintf("%s %s", tab.icon, tab.name)
		renderedTabs = append(renderedTabs, style.Render(label))
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	return lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 2).
		Render(tabBar)
}
