package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
)

func init() {
	registerFactCollector("codeartifact-resource-policy", "regional", collectCodeartifactPolicies)
}

// collectCodeartifactPolicies emits CodeArtifact domain and repository
// resource-based policies as resource_policy facts (CrossAccountTrust surface).
// A domain or repository with no policy is skipped without error.
func collectCodeartifactPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := codeartifact.NewFromConfig(c.cfg)
	ro := func(o *codeartifact.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	// --- domains ---
	dp := codeartifact.NewListDomainsPaginator(svc, &codeartifact.ListDomainsInput{})
	for dp.HasMorePages() {
		out, err := dp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, d := range out.Domains {
			pol, e := svc.GetDomainPermissionsPolicy(ctx, &codeartifact.GetDomainPermissionsPolicyInput{
				Domain:      d.Name,
				DomainOwner: d.Owner,
			}, ro)
			if e != nil || pol.Policy == nil || pol.Policy.Document == nil {
				continue // no policy on this domain
			}
			arn := firstNonEmpty(aws.ToString(d.Arn), "arn:aws:codeartifact:"+region+":"+aws.ToString(d.Owner)+":domain/"+aws.ToString(d.Name))
			s.emitFact("resource_policy", "CrossAccountTrust", scope, arn, "",
				map[string]any{"policy": aws.ToString(pol.Policy.Document)})
		}
	}

	// --- repositories ---
	rp := codeartifact.NewListRepositoriesPaginator(svc, &codeartifact.ListRepositoriesInput{})
	for rp.HasMorePages() {
		out, err := rp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, r := range out.Repositories {
			pol, e := svc.GetRepositoryPermissionsPolicy(ctx, &codeartifact.GetRepositoryPermissionsPolicyInput{
				Domain:      r.DomainName,
				DomainOwner: r.DomainOwner,
				Repository:  r.Name,
			}, ro)
			if e != nil || pol.Policy == nil || pol.Policy.Document == nil {
				continue // no policy on this repository
			}
			arn := firstNonEmpty(aws.ToString(r.Arn), "arn:aws:codeartifact:"+region+":"+aws.ToString(r.DomainOwner)+":repository/"+aws.ToString(r.DomainName)+"/"+aws.ToString(r.Name))
			s.emitFact("resource_policy", "CrossAccountTrust", scope, arn, "",
				map[string]any{"policy": aws.ToString(pol.Policy.Document)})
		}
	}

	return s.n - start, nil
}
