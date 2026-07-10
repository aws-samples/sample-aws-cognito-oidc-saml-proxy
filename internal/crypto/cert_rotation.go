package crypto

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// CertRotationConfig controls the rotation schedule.
type CertRotationConfig struct {
	RotationWindowDays int // Start rotation this many days before expiry (default: 30)
	PromotionDelayDays int // Wait this many days after staging before promoting (default: 14)
}

// DefaultRotationConfig returns sensible defaults.
func DefaultRotationConfig() CertRotationConfig {
	return CertRotationConfig{
		RotationWindowDays: 30,
		PromotionDelayDays: 14,
	}
}

// CertRotationResult describes the outcome of a rotation check.
type CertRotationResult struct {
	DaysRemaining float64
	Action        string
}

// CheckCertRotation examines the active cert and performs rotation steps as needed.
// It implements a three-phase state machine:
//  1. No active cert -> generate initial certificate
//  2. Within rotation window, no next cert -> stage next certificate
//  3. Past promotion threshold -> promote next to active
func CheckCertRotation(ctx context.Context, certStore *CertStore, signer *KMSSigner, entityID string, cfg CertRotationConfig) (CertRotationResult, error) {
	// Load active cert expiry
	expiry, err := certStore.GetActiveCertExpiry(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// A transient/operational error (throttling, 5xx, IAM denial, network
		// blip) must NOT be mistaken for "no cert exists": generating a fresh
		// self-signed cert here would clobber a live — possibly CA-issued —
		// active cert (StoreActiveCert stamps Source=SelfSigned, and the
		// CA-issued guard below only runs after a successful expiry read). Fail
		// closed and leave the existing cert untouched.
		return CertRotationResult{}, fmt.Errorf("failed to read active cert expiry: %w", err)
	}
	if err != nil {
		// Confirmed not-found (errors.Is store.ErrNotFound) -- generate the first one.
		cert, genErr := GenerateSelfSignedCert(signer, entityID)
		if genErr != nil {
			return CertRotationResult{}, fmt.Errorf("failed to generate initial cert: %w", genErr)
		}
		if storeErr := certStore.StoreActiveCert(ctx, cert); storeErr != nil {
			return CertRotationResult{}, fmt.Errorf("failed to store initial cert: %w", storeErr)
		}
		days := time.Until(cert.NotAfter).Hours() / 24
		slog.InfoContext(ctx, "generated initial signing certificate",
			"expiresAt", cert.NotAfter,
			"daysRemaining", days,
		)
		return CertRotationResult{DaysRemaining: days, Action: "generated_initial"}, nil
	}

	daysRemaining := time.Until(expiry).Hours() / 24
	slog.InfoContext(ctx, "cert rotation check",
		"daysRemaining", daysRemaining,
		"expiry", expiry,
	)

	// Not within rotation window -- nothing to do
	if daysRemaining > float64(cfg.RotationWindowDays) {
		return CertRotationResult{DaysRemaining: daysRemaining, Action: "no_action"}, nil
	}

	// If the active cert was issued by an external CA, automatic self-signed
	// rotation must not run -- it would replace the CA-issued cert with a
	// self-signed one. Surface an action so an operator re-runs the CSR/import
	// flow or promotes the standby backup before expiry.
	if rec, recErr := certStore.GetActiveCertRecord(ctx); recErr == nil && rec.Source == SourceCAIssued {
		slog.WarnContext(ctx, "active certificate is CA-issued; automatic rotation skipped",
			"daysRemaining", daysRemaining,
		)
		return CertRotationResult{DaysRemaining: daysRemaining, Action: "import_required"}, nil
	}

	// Within rotation window -- check if next cert is staged
	_, nextErr := certStore.GetNextCert(ctx)
	if nextErr != nil && !errors.Is(nextErr, store.ErrNotFound) {
		// As above: a transient error reading the staged cert must not be read
		// as "not staged" and trigger a redundant generate/store. Fail closed.
		return CertRotationResult{DaysRemaining: daysRemaining}, fmt.Errorf("failed to read staged next cert: %w", nextErr)
	}
	if nextErr != nil {
		// Confirmed not-found -- stage one.
		cert, genErr := GenerateSelfSignedCert(signer, entityID)
		if genErr != nil {
			return CertRotationResult{DaysRemaining: daysRemaining}, fmt.Errorf("failed to generate next cert: %w", genErr)
		}
		if storeErr := certStore.StoreNextCert(ctx, cert); storeErr != nil {
			return CertRotationResult{DaysRemaining: daysRemaining}, fmt.Errorf("failed to store next cert: %w", storeErr)
		}
		slog.InfoContext(ctx, "staged next signing certificate for rotation",
			"nextExpiresAt", cert.NotAfter,
		)
		return CertRotationResult{DaysRemaining: daysRemaining, Action: "staged_next"}, nil
	}

	// Next cert exists -- check if promotion window has passed
	promotionThreshold := float64(cfg.RotationWindowDays - cfg.PromotionDelayDays)
	if daysRemaining <= promotionThreshold {
		if promErr := certStore.PromoteNextToActive(ctx); promErr != nil {
			return CertRotationResult{DaysRemaining: daysRemaining}, fmt.Errorf("failed to promote cert: %w", promErr)
		}
		// Read new expiry after promotion
		newExpiry, _ := certStore.GetActiveCertExpiry(ctx)
		newDays := time.Until(newExpiry).Hours() / 24
		slog.InfoContext(ctx, "promoted next cert to active",
			"newExpiresAt", newExpiry,
			"newDaysRemaining", newDays,
		)
		return CertRotationResult{DaysRemaining: newDays, Action: "promoted"}, nil
	}

	return CertRotationResult{DaysRemaining: daysRemaining, Action: "waiting_for_promotion"}, nil
}
