package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

func init() {
	registerFactCollector("opensearch-resource-policy", "regional", collectOpensearchPolicies)
}

// collectOpensearchPolicies emits OpenSearch domain access policies as
// resource_policy facts (CrossAccountTrust surface). Domains with no access
// policy set are skipped without error.
func collectOpensearchPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := opensearch.NewFromConfig(c.cfg)
	ro := func(o *opensearch.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	out, err := svc.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{}, ro)
	if err != nil {
		return 0, err
	}

	for _, d := range out.DomainNames {
		desc, e := svc.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: d.DomainName,
		}, ro)
		if e != nil || desc.DomainStatus == nil || desc.DomainStatus.AccessPolicies == nil {
			continue // no policy on this domain
		}
		policy := aws.ToString(desc.DomainStatus.AccessPolicies)
		if policy == "" {
			continue
		}
		arn := firstNonEmpty(aws.ToString(desc.DomainStatus.ARN), aws.ToString(d.DomainName))
		s.emitFact("resource_policy", "CrossAccountTrust", scope, arn, "",
			map[string]any{"policy": policy})
	}

	return s.n - start, nil
}
