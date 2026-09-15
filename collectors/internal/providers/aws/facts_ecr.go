package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

func init() { registerFactCollector("ecr-resource-policy", "regional", collectEcrPolicies) }

// collectEcrPolicies emits ECR resource-based policies as resource_policy facts
// (CrossAccountTrust surface). It collects two kinds of policies per region:
//
//  1. Per-repository policies — fetched via GetRepositoryPolicy for each
//     repository returned by DescribeRepositories. Repositories with no policy
//     attached are silently skipped.
//
//  2. Registry policy — a single cross-account replication/pull-through policy
//     that applies to the entire private registry in this region. Absent when
//     never set; silently skipped.
func collectEcrPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := ecr.NewFromConfig(c.cfg)
	ro := func(o *ecr.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	// --- Per-repository policies ---
	p := ecr.NewDescribeRepositoriesPaginator(svc, &ecr.DescribeRepositoriesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, repo := range out.Repositories {
			name := aws.ToString(repo.RepositoryName)
			if name == "" {
				continue
			}
			pol, e := svc.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
				RepositoryName: aws.String(name),
			}, ro)
			if e != nil || pol.PolicyText == nil {
				continue // no policy on this repository
			}
			arn := firstNonEmpty(aws.ToString(repo.RepositoryArn),
				fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s",
					region, aws.ToString(repo.RegistryId), name))
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				arn, "", map[string]any{"policy": aws.ToString(pol.PolicyText)})
		}
	}

	// --- Registry-level policy (one per private registry per region) ---
	regPol, err := svc.GetRegistryPolicy(ctx, &ecr.GetRegistryPolicyInput{}, ro)
	if err == nil && regPol.PolicyText != nil {
		registryArn := fmt.Sprintf("arn:aws:ecr:%s:%s:registry", region, aws.ToString(regPol.RegistryId))
		s.emitFact("resource_policy", "CrossAccountTrust", scope,
			registryArn, "", map[string]any{"policy": aws.ToString(regPol.PolicyText)})
	}

	return s.n - start, nil
}
