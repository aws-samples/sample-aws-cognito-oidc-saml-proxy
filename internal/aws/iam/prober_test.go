package iam

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubIAM struct {
	calls     atomic.Int32
	lastInput *awsiam.SimulatePrincipalPolicyInput
	perAction map[string]iamtypes.PolicyEvaluationDecisionType
	returnErr error
}

func (s *stubIAM) SimulatePrincipalPolicy(ctx context.Context, in *awsiam.SimulatePrincipalPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.SimulatePrincipalPolicyOutput, error) {
	s.calls.Add(1)
	s.lastInput = in
	if s.returnErr != nil {
		return nil, s.returnErr
	}
	results := make([]iamtypes.EvaluationResult, 0, len(in.ActionNames))
	for _, act := range in.ActionNames {
		decision := iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		if d, ok := s.perAction[act]; ok {
			decision = d
		}
		action := act
		results = append(results, iamtypes.EvaluationResult{
			EvalActionName: &action,
			EvalDecision:   decision,
		})
	}
	return &awsiam.SimulatePrincipalPolicyOutput{EvaluationResults: results}, nil
}

const (
	testRoleArn = "arn:aws:iam::123456789012:role/identity-gateway-acme"
)

func TestProber_AllActionsAllowed(t *testing.T) {
	stub := &stubIAM{
		perAction: map[string]iamtypes.PolicyEvaluationDecisionType{
			"cognito-idp:DescribeUserPool":       iamtypes.PolicyEvaluationDecisionTypeAllowed,
			"cognito-idp:DescribeUserPoolClient": iamtypes.PolicyEvaluationDecisionTypeAllowed,
		},
	}
	p := NewProber(stub)

	result, err := p.Simulate(context.Background(), testRoleArn, []string{
		"cognito-idp:DescribeUserPool",
		"cognito-idp:DescribeUserPoolClient",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{
		"cognito-idp:DescribeUserPool":       true,
		"cognito-idp:DescribeUserPoolClient": true,
	}, result)
	assert.Equal(t, int32(1), stub.calls.Load(), "one batched call, not one per action")
	require.NotNil(t, stub.lastInput.PolicySourceArn)
	assert.Equal(t, testRoleArn, *stub.lastInput.PolicySourceArn)
}

func TestProber_MixedDecisions(t *testing.T) {
	stub := &stubIAM{
		perAction: map[string]iamtypes.PolicyEvaluationDecisionType{
			"cognito-idp:ListUsers":       iamtypes.PolicyEvaluationDecisionTypeAllowed,
			"cognito-idp:AdminCreateUser": iamtypes.PolicyEvaluationDecisionTypeExplicitDeny,
		},
	}
	p := NewProber(stub)

	result, err := p.Simulate(context.Background(), testRoleArn, []string{
		"cognito-idp:ListUsers",
		"cognito-idp:AdminCreateUser",
		"cognito-idp:AdminDisableUser",
	})
	require.NoError(t, err)
	assert.True(t, result["cognito-idp:ListUsers"])
	assert.False(t, result["cognito-idp:AdminCreateUser"], "explicit deny → false")
	assert.False(t, result["cognito-idp:AdminDisableUser"], "implicit deny → false")
}

func TestProber_RejectsEmptyActions(t *testing.T) {
	stub := &stubIAM{}
	p := NewProber(stub)

	_, err := p.Simulate(context.Background(), testRoleArn, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actions must be non-empty")
	assert.Equal(t, int32(0), stub.calls.Load(), "must not call AWS with empty ActionNames")
}

func TestProber_RejectsEmptyRoleArn(t *testing.T) {
	stub := &stubIAM{}
	p := NewProber(stub)

	_, err := p.Simulate(context.Background(), "", []string{"cognito-idp:DescribeUserPool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PolicySourceArn is required")
}

func TestProber_PropagatesSimulateError(t *testing.T) {
	stub := &stubIAM{returnErr: errors.New("AccessDenied: SimulatePrincipalPolicy")}
	p := NewProber(stub)

	_, err := p.Simulate(context.Background(), testRoleArn, []string{"cognito-idp:ListUsers"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestProber_PaginationHandled(t *testing.T) {
	stub := &paginatingStubIAM{
		pages: [][]iamtypes.EvaluationResult{
			{evalResult("cognito-idp:DescribeUserPool", iamtypes.PolicyEvaluationDecisionTypeAllowed)},
			{evalResult("cognito-idp:ListUsers", iamtypes.PolicyEvaluationDecisionTypeAllowed)},
		},
	}
	p := NewProber(stub)

	result, err := p.Simulate(context.Background(), testRoleArn, []string{
		"cognito-idp:DescribeUserPool", "cognito-idp:ListUsers",
	})
	require.NoError(t, err)
	assert.True(t, result["cognito-idp:DescribeUserPool"])
	assert.True(t, result["cognito-idp:ListUsers"])
}

type paginatingStubIAM struct {
	pages [][]iamtypes.EvaluationResult
	idx   int
}

func (s *paginatingStubIAM) SimulatePrincipalPolicy(ctx context.Context, in *awsiam.SimulatePrincipalPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.SimulatePrincipalPolicyOutput, error) {
	if s.idx >= len(s.pages) {
		return &awsiam.SimulatePrincipalPolicyOutput{}, nil
	}
	page := s.pages[s.idx]
	s.idx++
	isTruncated := s.idx < len(s.pages)
	var marker *string
	if isTruncated {
		m := "next-page-marker"
		marker = &m
	}
	return &awsiam.SimulatePrincipalPolicyOutput{
		EvaluationResults: page,
		IsTruncated:       isTruncated,
		Marker:            marker,
	}, nil
}

func evalResult(action string, decision iamtypes.PolicyEvaluationDecisionType) iamtypes.EvaluationResult {
	a := action
	return iamtypes.EvaluationResult{
		EvalActionName: &a,
		EvalDecision:   decision,
	}
}

func TestProber_PassesResourceArns(t *testing.T) {
	stub := &stubIAM{
		perAction: map[string]iamtypes.PolicyEvaluationDecisionType{
			"secretsmanager:GetSecretValue": iamtypes.PolicyEvaluationDecisionTypeAllowed,
		},
	}
	p := NewProber(stub)

	_, err := p.Simulate(context.Background(), testRoleArn,
		[]string{"secretsmanager:GetSecretValue"},
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:my-secret-AB1234")
	require.NoError(t, err)

	require.NotNil(t, stub.lastInput)
	require.Len(t, stub.lastInput.ResourceArns, 1, "ResourceArns must be passed to AWS when provided")
	assert.Equal(t, "arn:aws:secretsmanager:us-east-1:111122223333:secret:my-secret-AB1234", stub.lastInput.ResourceArns[0])
}

var _ = aws.String
