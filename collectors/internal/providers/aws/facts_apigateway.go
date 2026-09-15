package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func init() {
	registerFactCollector("apigateway-resource-policy", "regional", collectApigatewayPolicies)
}

// collectApigatewayPolicies emits API Gateway REST API resource-based policies
// as resource_policy facts (CrossAccountTrust surface). The policy is stored on
// the RestApi object itself — no separate GetPolicy call is needed. APIs with no
// policy (nil or empty) are skipped without error.
func collectApigatewayPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := apigateway.NewFromConfig(c.cfg)
	ro := func(o *apigateway.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := apigateway.NewGetRestApisPaginator(svc, &apigateway.GetRestApisInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, api := range out.Items {
			if api.Policy == nil || aws.ToString(api.Policy) == "" {
				continue // no resource-based policy on this REST API
			}
			id := aws.ToString(api.Id)
			arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, id)
			s.emitFact("resource_policy", "CrossAccountTrust", scope, arn, "",
				map[string]any{"policy": urlDecode(aws.ToString(api.Policy))})
		}
	}
	return s.n - start, nil
}
