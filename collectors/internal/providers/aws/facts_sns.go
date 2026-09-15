package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

func init() { registerFactCollector("sns-resource-policy", "regional", collectSnsPolicies) }

// collectSnsPolicies emits SNS topic resource-based policies as resource_policy
// facts (CrossAccountTrust surface). Topics with no access control policy set
// are silently skipped.
func collectSnsPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := sns.NewFromConfig(c.cfg)
	ro := func(o *sns.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := sns.NewListTopicsPaginator(svc, &sns.ListTopicsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, t := range out.Topics {
			arn := aws.ToString(t.TopicArn)
			if arn == "" {
				continue
			}
			attrs, e := svc.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: aws.String(arn),
			}, ro)
			if e != nil || attrs == nil {
				continue // topic inaccessible or deleted — skip
			}
			policy, ok := attrs.Attributes["Policy"]
			if !ok || policy == "" {
				continue // no resource-based policy on this topic
			}
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": policy})
		}
	}
	return s.n - start, nil
}
