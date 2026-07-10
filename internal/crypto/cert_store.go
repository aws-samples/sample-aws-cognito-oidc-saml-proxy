package crypto

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/store"
)

// CertStore manages signing certificates in DynamoDB.
type CertStore struct {
	db store.TableAPI
}

// NewCertStore creates a new CertStore backed by the given table.
func NewCertStore(db store.TableAPI) *CertStore {
	return &CertStore{db: db}
}

// certItem is the DynamoDB item for a stored certificate.
type certItem struct {
	PK        string    `dynamo:"PK,hash" json:"-"`
	SK        string    `dynamo:"SK,range" json:"-"`
	CertPEM   string    `dynamo:"certPem" json:"certPem"`
	NotBefore time.Time `dynamo:"notBefore" json:"notBefore"`
	NotAfter  time.Time `dynamo:"notAfter" json:"notAfter"`
	Serial    string    `dynamo:"serial" json:"serial"`
	CreatedAt time.Time `dynamo:"createdAt" json:"createdAt"`
	// Source records how the cert was produced: SourceSelfSigned or SourceCAIssued.
	Source string `dynamo:"source,omitempty" json:"source,omitempty"`
	// KMSKeyID records which KMS key the cert's public key belongs to. Empty
	// means the gateway's primary signing key.
	KMSKeyID string `dynamo:"kmsKeyId,omitempty" json:"kmsKeyId,omitempty"`
}

const (
	certPK       = "SYSTEM#CONFIG"
	certActiveSK = "SYSTEM#SIGNING_CERT"
	certNextSK   = "SYSTEM#SIGNING_CERT_NEXT"
	certBackupSK = "SYSTEM#SIGNING_CERT_BACKUP"
)

// CertMeta carries provenance metadata stored alongside a certificate.
type CertMeta struct {
	Source   string // SourceSelfSigned or SourceCAIssued
	KMSKeyID string // KMS key the cert's public key belongs to ("" = primary)
}

// CertRecord is a stored certificate together with its provenance metadata.
type CertRecord struct {
	Certificate *x509.Certificate
	Source      string
	KMSKeyID    string
}

// GetActiveCert returns the active signing certificate, or nil if none exists.
func (s *CertStore) GetActiveCert(ctx context.Context) (*x509.Certificate, error) {
	return s.getCert(ctx, certActiveSK)
}

// GetNextCert returns the pre-staged next certificate, or nil if none exists.
func (s *CertStore) GetNextCert(ctx context.Context) (*x509.Certificate, error) {
	return s.getCert(ctx, certNextSK)
}

// GetAllCerts returns all distinct certificates (active + next + backup if they
// exist), deduplicated by serial number. Used by SAML metadata to publish every
// cert relying parties may need to trust during rotation or a backup promotion.
func (s *CertStore) GetAllCerts(ctx context.Context) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	seen := map[string]bool{}
	add := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		key := c.SerialNumber.String()
		if seen[key] {
			return
		}
		seen[key] = true
		certs = append(certs, c)
	}
	if active, err := s.GetActiveCert(ctx); err == nil {
		add(active)
	}
	if next, err := s.GetNextCert(ctx); err == nil {
		add(next)
	}
	if backup, err := s.GetBackupCert(ctx); err == nil {
		add(backup)
	}
	return certs, nil
}

// GetActiveCertExpiry returns the NotAfter time of the active cert.
func (s *CertStore) GetActiveCertExpiry(ctx context.Context) (time.Time, error) {
	var item certItem
	if err := s.db.Get(ctx, certPK, certActiveSK, &item); err != nil {
		return time.Time{}, fmt.Errorf("no active cert: %w", err)
	}
	return item.NotAfter, nil
}

// GetBackupCert returns the standby backup signing certificate, or nil if none.
func (s *CertStore) GetBackupCert(ctx context.Context) (*x509.Certificate, error) {
	return s.getCert(ctx, certBackupSK)
}

// GetActiveCertRecord returns the active cert together with its provenance metadata.
func (s *CertStore) GetActiveCertRecord(ctx context.Context) (*CertRecord, error) {
	return s.getCertRecord(ctx, certActiveSK)
}

// GetBackupCertRecord returns the backup cert together with its provenance metadata.
func (s *CertStore) GetBackupCertRecord(ctx context.Context) (*CertRecord, error) {
	return s.getCertRecord(ctx, certBackupSK)
}

// StoreActiveCert stores a certificate as the active signing cert (self-signed).
func (s *CertStore) StoreActiveCert(ctx context.Context, cert *x509.Certificate) error {
	return s.storeCert(ctx, certActiveSK, cert, CertMeta{Source: SourceSelfSigned})
}

// StoreActiveCertMeta stores a certificate as the active signing cert with metadata.
func (s *CertStore) StoreActiveCertMeta(ctx context.Context, cert *x509.Certificate, meta CertMeta) error {
	return s.storeCert(ctx, certActiveSK, cert, meta)
}

// StoreNextCert stores a certificate as the pre-staged next cert (self-signed).
func (s *CertStore) StoreNextCert(ctx context.Context, cert *x509.Certificate) error {
	return s.storeCert(ctx, certNextSK, cert, CertMeta{Source: SourceSelfSigned})
}

// StoreBackupCertMeta stores a certificate in the standby backup slot.
func (s *CertStore) StoreBackupCertMeta(ctx context.Context, cert *x509.Certificate, meta CertMeta) error {
	return s.storeCert(ctx, certBackupSK, cert, meta)
}

// PromoteNextToActive replaces the active cert with the next cert and deletes next.
func (s *CertStore) PromoteNextToActive(ctx context.Context) error {
	rec, err := s.getCertRecord(ctx, certNextSK)
	if err != nil {
		return fmt.Errorf("no next cert to promote: %w", err)
	}
	if err := s.storeCert(ctx, certActiveSK, rec.Certificate, CertMeta{Source: rec.Source, KMSKeyID: rec.KMSKeyID}); err != nil {
		return fmt.Errorf("failed to promote cert: %w", err)
	}
	return s.DeleteNext(ctx)
}

// PromoteBackupToActive replaces the active cert with the backup cert and clears
// the backup slot. This is the fast-path rollover for expiry or key rolling: the
// backup is already published in SAML metadata, so relying parties already trust
// it at the moment of promotion.
func (s *CertStore) PromoteBackupToActive(ctx context.Context) error {
	rec, err := s.getCertRecord(ctx, certBackupSK)
	if err != nil {
		return fmt.Errorf("no backup cert to promote: %w", err)
	}
	if err := s.storeCert(ctx, certActiveSK, rec.Certificate, CertMeta{Source: rec.Source, KMSKeyID: rec.KMSKeyID}); err != nil {
		return fmt.Errorf("failed to promote backup cert: %w", err)
	}
	return s.DeleteBackup(ctx)
}

// DeleteNext removes the pre-staged next cert.
func (s *CertStore) DeleteNext(ctx context.Context) error {
	return s.db.Delete(ctx, certPK, certNextSK)
}

// DeleteBackup removes the standby backup cert.
func (s *CertStore) DeleteBackup(ctx context.Context) error {
	return s.db.Delete(ctx, certPK, certBackupSK)
}

func (s *CertStore) getCert(ctx context.Context, sk string) (*x509.Certificate, error) {
	rec, err := s.getCertRecord(ctx, sk)
	if err != nil {
		return nil, err
	}
	return rec.Certificate, nil
}

func (s *CertStore) getCertRecord(ctx context.Context, sk string) (*CertRecord, error) {
	var item certItem
	if err := s.db.Get(ctx, certPK, sk, &item); err != nil {
		return nil, err
	}
	if item.CertPEM == "" {
		return nil, fmt.Errorf("cert PEM is empty")
	}
	cert, err := PEMToCert([]byte(item.CertPEM))
	if err != nil {
		return nil, err
	}
	return &CertRecord{Certificate: cert, Source: item.Source, KMSKeyID: item.KMSKeyID}, nil
}

func (s *CertStore) storeCert(ctx context.Context, sk string, cert *x509.Certificate, meta CertMeta) error {
	source := meta.Source
	if source == "" {
		source = SourceSelfSigned
	}
	item := certItem{
		PK:        certPK,
		SK:        sk,
		CertPEM:   string(CertToPEM(cert)),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Serial:    cert.SerialNumber.String(),
		CreatedAt: time.Now(),
		Source:    source,
		KMSKeyID:  meta.KMSKeyID,
	}
	return s.db.Put(ctx, &item)
}
