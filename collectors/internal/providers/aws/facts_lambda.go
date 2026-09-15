package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func init() { registerFactCollector("lambda-resource-policy", "regional", collectLambdaPolicies) }

// collectLambdaPolicies emits Lambda function resource-based policies as
// resource_policy facts (CrossAccountTrust surface). Functions that have no
// policy attached — Lambda returns ResourceNotFoundException in that case —
// are silently skipped.
func collectLambdaPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := lambda.NewFromConfig(c.cfg)
	ro := func(o *lambda.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := lambda.NewListFunctionsPaginator(svc, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, f := range out.Functions {
			arn := aws.ToString(f.FunctionArn)
			if arn == "" {
				continue
			}
			pol, e := svc.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(arn)}, ro)
			if e != nil || pol.Policy == nil {
				continue // no policy on this function
			}
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
