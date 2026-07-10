package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/tui"
)

func main() {
	// API URL from environment or default.
	apiURL := "http://localhost:8080"
	if v := os.Getenv("FEDCTL_API_URL"); v != "" {
		apiURL = v
	}

	// Bearer token from the environment. This is a Cognito-issued JWT; the
	// management gateway (middleware.RequireAuth) validates it as
	// "Authorization: Bearer <jwt>" and rejects every unauthenticated mutation.
	// Sourced from an env var to mirror how FEDCTL_API_URL is provided.
	token := os.Getenv("FEDCTL_TOKEN")

	// Offline mode is an explicit, operator-selected opt-in that runs the TUI
	// against local mock data without contacting the API. It is the ONLY
	// sanctioned way to run without a token — a missing token never silently
	// falls back to mock data.
	offline := os.Getenv("FEDCTL_OFFLINE") != ""

	// Fail closed: refuse to start unauthenticated unless offline mode was
	// consciously requested. This prevents the tool from silently degrading to
	// mock data (or, against a misconfigured gateway, issuing unauthenticated
	// privileged calls) when no credential is present.
	if token == "" && !offline {
		fmt.Fprintln(os.Stderr, "fedctl: not authenticated: set FEDCTL_TOKEN to a Cognito-issued JWT bearer token.")
		fmt.Fprintln(os.Stderr, "        To run against local mock data instead, set FEDCTL_OFFLINE=1 explicitly.")
		os.Exit(1)
	}

	// Create API client.
	client := tui.NewAPIClient(apiURL, token, offline)

	// Create and run the TUI application.
	p := tea.NewProgram(tui.NewApp(client), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
