package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/guregu/dynamo/v2"
)

// ErrNotFound is returned when an item is not found in the store.
var ErrNotFound = errors.New("not found")

// ErrConditionFailed is returned by PutIfNotExists when the item already
// exists (the attribute_not_exists condition failed). Callers that need to
// distinguish "already present" from a transient store error must compare
// against this sentinel with errors.Is — never fail open on it.
var ErrConditionFailed = errors.New("conditional check failed: item already exists")

// generateID generates a random ID for use as a primary key.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// TableAPI abstracts DynamoDB table operations for testability.
// Production uses DynamoDB via guregu/dynamo; tests use MemoryDB.
type TableAPI interface {
	Put(ctx context.Context, item interface{}) error
	PutIfNotExists(ctx context.Context, item interface{}) error
	Get(ctx context.Context, pk, sk string, out interface{}) error
	Query(ctx context.Context, pk string, skPrefix string, out interface{}) error
	QueryGSI(ctx context.Context, indexName, gsiPK string, out interface{}) error
	Delete(ctx context.Context, pk, sk string) error
}

// DB wraps a guregu/dynamo Table for production DynamoDB access.
type DB struct {
	table dynamo.Table
}

// NewDB creates a DB backed by a real DynamoDB table.
func NewDB(db *dynamo.DB, tableName string) *DB {
	return &DB{table: db.Table(tableName)}
}

func (d *DB) Put(ctx context.Context, item interface{}) error {
	return d.table.Put(item).Run(ctx)
}

func (d *DB) PutIfNotExists(ctx context.Context, item interface{}) error {
	err := d.table.Put(item).If("attribute_not_exists(PK)").Run(ctx)
	if err != nil && dynamo.IsCondCheckFailed(err) {
		return ErrConditionFailed
	}
	return err
}

func (d *DB) Get(ctx context.Context, pk, sk string, out interface{}) error {
	return translateGetErr(d.table.Get("PK", pk).Range("SK", dynamo.Equal, sk).One(ctx, out))
}

// translateGetErr maps guregu/dynamo's not-found sentinel onto the store's own
// ErrNotFound so callers can branch on errors.Is(err, store.ErrNotFound). Any
// other error is returned verbatim. Without this, a real DynamoDB miss would
// surface as an unrecognized error and handlers would return 500 instead of 404.
func translateGetErr(err error) error {
	if errors.Is(err, dynamo.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func (d *DB) Query(ctx context.Context, pk string, skPrefix string, out interface{}) error {
	q := d.table.Get("PK", pk)
	if skPrefix != "" {
		q = q.Range("SK", dynamo.BeginsWith, skPrefix)
	}
	return q.All(ctx, out)
}

func (d *DB) QueryGSI(ctx context.Context, indexName, gsiPK string, out interface{}) error {
	return d.table.Get("GSI1PK", gsiPK).Index(indexName).All(ctx, out)
}

func (d *DB) Delete(ctx context.Context, pk, sk string) error {
	return d.table.Delete("PK", pk).Range("SK", sk).Run(ctx)
}

// ScanByPKPrefix scans items whose PK starts with the given prefix.
// Used by AuditStore.GetRecentSteps to read recent audit events from the session table.
func (d *DB) ScanByPKPrefix(ctx context.Context, prefix string, out interface{}) error {
	return d.table.Scan().Filter("begins_with(PK, ?)", prefix).All(ctx, out)
}
