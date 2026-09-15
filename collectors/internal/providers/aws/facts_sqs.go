package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func init() { registerFactCollector("sqs-resource-policy", "regional", collectSqsPolicies) }

// collectSqsPolicies emits SQS queue resource-based policies as resource_policy
// facts (CrossAccountTrust surface).
//
// SQS does not expose a dedicated GetQueuePolicy API; the policy is returned
// as one of the attributes via GetQueueAttributes. ListQueues returns queue
// URLs (not ARNs), so we fetch both the Policy and QueueArn attributes in a
// single call. Queues with no policy set return an empty/absent "Policy" key
// and are silently skipped.
func collectSqsPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := sqs.NewFromConfig(c.cfg)
	ro := func(o *sqs.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	attrNames := []types.QueueAttributeName{
		types.QueueAttributeNamePolicy,
		types.QueueAttributeNameQueueArn,
	}

	p := sqs.NewListQueuesPaginator(svc, &sqs.ListQueuesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, queueURL := range out.QueueUrls {
			attrs, e := svc.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl:       &queueURL,
				AttributeNames: attrNames,
			}, ro)
			if e != nil {
				continue // queue may have been deleted or access denied — skip
			}
			policy, ok := attrs.Attributes["Policy"]
			if !ok || policy == "" {
				continue // no resource-based policy on this queue
			}
			src := firstNonEmpty(attrs.Attributes["QueueArn"], queueURL)
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				src, "", map[string]any{"policy": policy})
		}
	}

	return s.n - start, nil
}
