// Package iam wraps the IAM SimulatePrincipalPolicy API for SaaS capability
// detection. Given the assumed-role's own ARN as PolicySourceArn, we can
// determine exactly which actions the role is permitted without performing
// those actions. Read-only and free — see docs.aws.amazon.com/IAM.
package iam

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// SimulatePrincipalPolicyAPI is the minimal IAM surface used by Prober.
// Declared for stubbing in tests.
type SimulatePrincipalPolicyAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, input *awsiam.SimulatePrincipalPolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.SimulatePrincipalPolicyOutput, error)
}

// Prober runs SimulatePrincipalPolicy against a target role.
type Prober struct {
	api SimulatePrincipalPolicyAPI
}

// NewProber returns a Prober backed by the given IAM client.
// In production, pass an IAM client constructed from a config that already
// carries the cross-account assumed-role credentials — see internal/aws/sts.Provider.
func NewProber(api SimulatePrincipalPolicyAPI) *Prober {
	return &Prober{api: api}
}

// Simulate evaluates whether `roleArn` is permitted to perform each action.
// If `resources` is non-empty, SimulatePrincipalPolicy is invoked with
// ResourceArns — critical for actions whose allow statements are scoped to
// specific ARNs (e.g., secretsmanager:GetSecretValue, kms:Decrypt). Passing
// nil/empty leaves ResourceArns unset, in which case AWS defaults to "*"
// which may return implicitDeny for resource-restricted policies.
//
// All actions in one call are evaluated against the same resource list. If
// different actions need different resources, call Simulate multiple times.
//
// Returns a map keyed by action name; value is true if the
// SimulatePrincipalPolicy decision was "allowed" and false otherwise.
//
// Pagination is handled transparently — AWS rarely paginates for <= 20 actions
// per call but the implementation follows the Marker chain for correctness.
func (p *Prober) Simulate(ctx context.Context, roleArn string, actions []string, resources ...string) (map[string]bool, error) {
	if roleArn == "" {
		return nil, fmt.Errorf("iam: PolicySourceArn is required")
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("iam: actions must be non-empty")
	}

	result := make(map[string]bool, len(actions))
	var marker *string
	for {
		in := &awsiam.SimulatePrincipalPolicyInput{
			PolicySourceArn: aws.String(roleArn),
			ActionNames:     actions,
		}
		if len(resources) > 0 {
			in.ResourceArns = resources
		}
		if marker != nil {
			in.Marker = marker
		}
		out, err := p.api.SimulatePrincipalPolicy(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("iam: SimulatePrincipalPolicy: %w", err)
		}
		for _, r := range out.EvaluationResults {
			if r.EvalActionName == nil {
				continue
			}
			result[*r.EvalActionName] = r.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	return result, nil
}
