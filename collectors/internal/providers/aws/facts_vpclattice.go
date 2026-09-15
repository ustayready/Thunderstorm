package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
)

func init() {
	registerFactCollector("vpclattice-resource-policy", "regional", collectVpclatticePolicies)
}

// collectVpclatticePolicies emits VPC Lattice resource-based policies as
// resource_policy facts (CrossAccountTrust surface). Two resource types carry
// policies in VPC Lattice:
//
//  1. Services — the logical application endpoint; shared cross-account via RAM,
//     which creates a GetResourcePolicy document. Services also carry a
//     GetAuthPolicy (IAM policy controlling which principals may invoke the
//     service), which is equally relevant as a principal-grant surface.
//
//  2. Service Networks — the network-level grouping; likewise supports both
//     GetResourcePolicy (RAM sharing) and GetAuthPolicy.
//
// Resources that return no policy (404 / empty) are silently skipped.
func collectVpclatticePolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := vpclattice.NewFromConfig(c.cfg)
	ro := func(o *vpclattice.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	// --- Services ---
	sp := vpclattice.NewListServicesPaginator(svc, &vpclattice.ListServicesInput{})
	for sp.HasMorePages() {
		out, err := sp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, svc2 := range out.Items {
			arn := aws.ToString(svc2.Arn)
			if arn == "" {
				continue
			}

			// Resource policy (created by RAM when the service is shared cross-account)
			rp, e := svc.GetResourcePolicy(ctx, &vpclattice.GetResourcePolicyInput{
				ResourceArn: aws.String(arn),
			}, ro)
			if e == nil && rp.Policy != nil {
				s.emitFact("resource_policy", "CrossAccountTrust", scope,
					arn, "", map[string]any{"policy": aws.ToString(rp.Policy)})
			}

			// Auth policy (IAM policy controlling which principals can invoke the service)
			ap, e := svc.GetAuthPolicy(ctx, &vpclattice.GetAuthPolicyInput{
				ResourceIdentifier: aws.String(arn),
			}, ro)
			if e == nil && ap.Policy != nil {
				s.emitFact("resource_policy", "CrossAccountTrust", scope,
					arn, "", map[string]any{"policy": aws.ToString(ap.Policy), "policy_kind": "auth_policy"})
			}
		}
	}

	// --- Service Networks ---
	np := vpclattice.NewListServiceNetworksPaginator(svc, &vpclattice.ListServiceNetworksInput{})
	for np.HasMorePages() {
		out, err := np.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, sn := range out.Items {
			arn := aws.ToString(sn.Arn)
			if arn == "" {
				continue
			}

			// Resource policy (RAM sharing cross-account)
			rp, e := svc.GetResourcePolicy(ctx, &vpclattice.GetResourcePolicyInput{
				ResourceArn: aws.String(arn),
			}, ro)
			if e == nil && rp.Policy != nil {
				s.emitFact("resource_policy", "CrossAccountTrust", scope,
					arn, "", map[string]any{"policy": aws.ToString(rp.Policy)})
			}

			// Auth policy (controls which principals can access resources through this network)
			ap, e := svc.GetAuthPolicy(ctx, &vpclattice.GetAuthPolicyInput{
				ResourceIdentifier: aws.String(arn),
			}, ro)
			if e == nil && ap.Policy != nil {
				s.emitFact("resource_policy", "CrossAccountTrust", scope,
					arn, "", map[string]any{"policy": aws.ToString(ap.Policy), "policy_kind": "auth_policy"})
			}
		}
	}

	return s.n - start, nil
}
