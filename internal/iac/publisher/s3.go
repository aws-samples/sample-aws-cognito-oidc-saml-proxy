// Package publisher uploads rendered IaC artifacts to S3 for CloudFormation
// quick-create. CFN's quick-create URL fetches templateURL server-side and
// requires anonymous-GET HTTPS; signed URLs with bearer tokens fail silently.
//
// The bucket (provisioned in infra/iac_templates_bucket.tf) is PRIVATE — Block
// Public Access is on and no public-read policy is attached. The
// anonymous-GET surface CFN needs is provided by CloudFront: a templates/*
// cache behavior serves the objects over HTTPS and reaches the private bucket
// through an Origin Access Control identity, so the artifacts are readable at
// the edge without the bucket itself ever being public. Publish therefore emits
// CloudFront URLs (publicBaseURL is the gateway's CloudFront base URL, wired via
// PROXY_IAC_TEMPLATES_BASE_URL), not S3 virtual-hosted URLs. A 24-hour
// object-lifecycle rule expires the rendered templates.
package publisher

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// PutObjectAPI is the minimal S3 surface used by S3. Declared for stubbing.
type PutObjectAPI interface {
	PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3 publishes rendered IaC artifacts to a private bucket prefix that is served
// anonymously through CloudFront.
type S3 struct {
	api           PutObjectAPI
	bucket        string
	publicBaseURL string // CloudFront base URL, e.g. "https://d111111abcdef8.cloudfront.net"
}

// NewS3 returns a Publisher backed by the given S3 client.
// publicBaseURL is the host prefix (no trailing slash) at which objects are
// anonymously addressable — CloudFormation must be able to GET it without auth.
// It is the gateway's CloudFront base URL (the templates/* behavior fronts the
// private bucket via OAC); an S3 virtual-hosted host works only for the legacy
// public-bucket path and is used solely as a local-dev fallback.
func NewS3(api PutObjectAPI, bucket, publicBaseURL string) *S3 {
	return &S3{
		api:           api,
		bucket:        bucket,
		publicBaseURL: strings.TrimRight(publicBaseURL, "/"),
	}
}

// extensions maps format → file extension. Keep in lockstep with templates.Render.
var extensions = map[string]string{
	"cfn": ".yaml",
	"tf":  ".tf",
	"cli": ".sh",
}

var contentTypes = map[string]string{
	"cfn": "application/x-yaml",
	"tf":  "text/plain",
	"cli": "text/x-shellscript",
}

// Publish uploads the artifact under templates/<slug>/<randomID><ext> and
// returns the public URL. The random ID guarantees each regeneration gets a
// unique object so a CFN deploy in progress isn't overwritten.
func (p *S3) Publish(ctx context.Context, slug, format string, body []byte) (string, error) {
	ext, ok := extensions[format]
	if !ok {
		return "", fmt.Errorf("publisher: unknown format %q", format)
	}
	ct := contentTypes[format]

	randID, err := randomID(8)
	if err != nil {
		return "", fmt.Errorf("publisher: random id: %w", err)
	}
	key := fmt.Sprintf("templates/%s/%s%s", slug, randID, ext)

	if _, err := p.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(ct),
	}); err != nil {
		return "", fmt.Errorf("publisher: PutObject %s/%s: %w", p.bucket, key, err)
	}

	return fmt.Sprintf("%s/%s", p.publicBaseURL, key), nil
}

func randomID(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
