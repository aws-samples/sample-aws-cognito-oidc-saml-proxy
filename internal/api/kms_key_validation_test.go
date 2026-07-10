package api

import "testing"

func TestValidateTenantKMSKeyRefs(t *testing.T) {
	strict := KMSKeyPolicy{AccountID: "111122223333", Region: "eu-north-1", Strict: true}

	cases := []struct {
		name    string
		keyID   string
		keyArn  string
		policy  KMSKeyPolicy
		wantErr bool
	}{
		{name: "both empty is allowed", policy: strict, wantErr: false},
		{
			name:   "bare key UUID",
			keyID:  "1234abcd-12ab-34cd-56ef-1234567890ab",
			policy: strict,
		},
		{
			name:   "multi-region key id",
			keyID:  "mrk-1234567890abcdef1234567890abcdef",
			policy: strict,
		},
		{
			name:   "bare alias",
			keyID:  "alias/tenant-acme-signing",
			policy: strict,
		},
		{
			name:   "same-account key ARN",
			keyID:  "arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			policy: strict,
		},
		{
			name:   "same-account alias ARN in KMSKeyArn field",
			keyArn: "arn:aws:kms:eu-north-1:111122223333:alias/tenant-acme",
			policy: strict,
		},
		// --- rejections ---
		{
			name:    "cross-account key ARN rejected",
			keyID:   "arn:aws:kms:eu-north-1:999988887777:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "wrong-region key ARN rejected",
			keyID:   "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "non-kms service ARN rejected",
			keyID:   "arn:aws:s3:::my-bucket",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "non-key resource ARN rejected",
			keyID:   "arn:aws:kms:eu-north-1:111122223333:something/else",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "AWS-managed alias rejected",
			keyID:   "alias/aws/s3",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "AWS-managed alias ARN rejected",
			keyArn:  "arn:aws:kms:eu-north-1:111122223333:alias/aws/s3",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "garbage key ref rejected",
			keyID:   "'; DROP TABLE tenants; --",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "non-ARN in KMSKeyArn field rejected",
			keyArn:  "not-an-arn",
			policy:  strict,
			wantErr: true,
		},
		{
			name:    "strict gateway without account id refuses fully-qualified ARN",
			keyID:   "arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			policy:  KMSKeyPolicy{Region: "eu-north-1", Strict: true},
			wantErr: true,
		},
		{
			name:   "local dev without account id allows ARN (non-strict)",
			keyID:  "arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			policy: KMSKeyPolicy{Strict: false},
		},
		{
			name:   "empty resource id after key/ rejected",
			keyID:  "arn:aws:kms:eu-north-1:111122223333:key/",
			policy: strict, wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTenantKMSKeyRefs(tc.keyID, tc.keyArn, tc.policy)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
