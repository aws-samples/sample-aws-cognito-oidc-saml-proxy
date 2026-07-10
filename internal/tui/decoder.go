package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type DecoderModel struct {
	client     *APIClient
	input      textarea.Model
	viewport   viewport.Model
	decoded    string
	err        error
	decoding   bool
	width      int
	height     int
	focusInput bool
}

func NewDecoderModel(client *APIClient) DecoderModel {
	ta := textarea.New()
	ta.Placeholder = "Paste base64-encoded SAML assertion or JWT token here..."
	ta.SetWidth(80)
	ta.SetHeight(5)
	ta.Focus()

	vp := viewport.New(80, 20)
	vp.SetContent("")

	return DecoderModel{
		client:     client,
		input:      ta,
		viewport:   vp,
		focusInput: true,
	}
}

func (m DecoderModel) Init() tea.Cmd {
	return textarea.Blink
}

func (m DecoderModel) Update(msg tea.Msg) (DecoderModel, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Resize components
		m.input.SetWidth(msg.Width - 10)
		m.viewport.Width = msg.Width - 10
		m.viewport.Height = msg.Height - 20

	case AssertionDecodedMsg:
		m.decoding = false
		if msg.Err != nil {
			m.err = msg.Err
			m.decoded = ""
			m.viewport.SetContent(ErrorStyle.Render("Error: " + msg.Err.Error()))
		} else {
			m.err = nil
			m.decoded = msg.Decoded
			m.viewport.SetContent(msg.Decoded)
			m.viewport.GotoTop()
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+d":
			// Decode the input
			input := strings.TrimSpace(m.input.Value())
			if input != "" {
				m.decoding = true
				return m, m.client.DecodeAssertion(input)
			}

		case "ctrl+c":
			// Clear input
			m.input.Reset()
			m.decoded = ""
			m.viewport.SetContent("")
			return m, nil

		case "pgdown", "pgup":
			// Let viewport handle page up/down
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}
	}

	// Update input textarea
	if m.focusInput {
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	}

	// Update viewport
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m DecoderModel) View() string {
	var content strings.Builder

	// Title
	title := TitleStyle.Render("SAML/JWT Decoder")
	content.WriteString(title + "\n\n")

	// Input section
	inputBox := BoxStyle.Width(m.input.Width() + 4).Render(m.input.View())
	content.WriteString(inputBox + "\n\n")

	// Action hint
	actionHint := HelpStyle.Render("Press Ctrl+D to decode • Ctrl+C to clear")
	content.WriteString(actionHint + "\n\n")

	// Decoded output
	if m.decoding {
		content.WriteString(LoadingView() + "\n")
	} else if m.decoded != "" {
		outputTitle := lipgloss.NewStyle().Bold(true).Render("Decoded Output:")
		content.WriteString(outputTitle + "\n\n")

		outputBox := BoxStyle.Width(m.viewport.Width + 4).Height(m.viewport.Height + 2).Render(m.viewport.View())
		content.WriteString(outputBox + "\n")
	} else if m.err != nil {
		content.WriteString(ErrorStyle.Render("Error: "+m.err.Error()) + "\n")
	}

	// Help
	help := HelpStyle.Render("tab: next view • q: quit • PgUp/PgDn: scroll output")
	content.WriteString("\n" + help)

	return content.String()
}
