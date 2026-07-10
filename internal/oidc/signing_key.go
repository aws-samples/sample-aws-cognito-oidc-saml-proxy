package oidc

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/internal/crypto"
)

// signingKey implements op.SigningKey using a KMS-backed jose signer.
type signingKey struct {
	id     string
	signer *crypto.KMSJoseSigner
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (k *signingKey) Key() any {
	// Return the OpaqueSigner so zitadel/oidc can use it for JWT signing.
	return k.signer
}

func (k *signingKey) ID() string {
	return k.id
}

// publicKey implements op.Key for JWKS endpoint responses.
type publicKey struct {
	id  string
	jwk *jose.JSONWebKey
}

func (k *publicKey) ID() string {
	return k.id
}

func (k *publicKey) Algorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (k *publicKey) Use() string {
	return "sig"
}

func (k *publicKey) Key() any {
	// Return the actual public key from the JWK, not the JWK itself
	return k.jwk.Key
}
