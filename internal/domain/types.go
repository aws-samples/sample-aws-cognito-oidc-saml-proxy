package domain

import "time"

// FlowStep represents a single step in an authentication flow.
type FlowStep struct {
	FlowID     string            `dynamo:"flowId" json:"flowId"`
	Sequence   uint64            `dynamo:"sequence" json:"sequence"`
	StepType   string            `dynamo:"stepType" json:"stepType"`
	SPEntityID string            `dynamo:"spEntityId,omitempty" json:"spEntityId,omitempty"`
	UserID     string            `dynamo:"userId,omitempty" json:"userId,omitempty"`
	Timestamp  time.Time         `dynamo:"timestamp" json:"timestamp"`
	Payload    map[string]string `dynamo:"payload,omitempty" json:"payload,omitempty"`
}

// SessionParticipant represents an SP participating in a SAML session.
type SessionParticipant struct {
	SessionIndex string    `dynamo:"sessionIndex" json:"sessionIndex"`
	SPEntityID   string    `dynamo:"spEntityId" json:"spEntityId"`
	UserID       string    `dynamo:"userId" json:"userId"`
	NameID       string    `dynamo:"nameId" json:"nameId"`
	CreatedAt    time.Time `dynamo:"createdAt" json:"createdAt"`
	ExpiresAt    time.Time `dynamo:"expiresAt" json:"expiresAt"`
}
