package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

func init() { registerFactCollector("glue-resource-policy", "regional", collectGluePolicies) }

// collectGluePolicies emits Glue resource-based policies as resource_policy facts
// (CrossAccountTrust surface).
//
// Glue exposes two policy retrieval APIs:
//
//   - GetResourcePolicy (no ResourceArn) — returns the account-level Data Catalog
//     resource policy for the region. This is the primary cross-account grant
//     surface for Glue: it controls who can call Glue APIs against this account's
//     catalog. Absent when never configured; silently skipped.
//
//   - GetResourcePolicies — returns all resource policies set on individual
//     resources via Resource Access Manager, as well as the account-level catalog
//     policy again. The GluePolicy items include no resource ARN, so we emit each
//     one under a synthetic catalog ARN with its policy hash as a disambiguator.
//     Policies already captured via GetResourcePolicy are deduplicated by hash.
//
// We prefer GetResourcePolicy first (definitive catalog ARN) and then sweep
// GetResourcePolicies for any additional RAM-delegated policies.
func collectGluePolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := glue.NewFromConfig(c.cfg)
	ro := func(o *glue.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	catalogArn := fmt.Sprintf("arn:aws:glue:%s:%s:catalog", region, s.account)

	// --- Account-level Data Catalog resource policy ---
	catPol, err := svc.GetResourcePolicy(ctx, &glue.GetResourcePolicyInput{}, ro)
	seenHash := ""
	if err == nil && catPol.PolicyInJson != nil {
		s.emitFact("resource_policy", "CrossAccountTrust", scope,
			catalogArn, "", map[string]any{"policy": aws.ToString(catPol.PolicyInJson)})
		seenHash = aws.ToString(catPol.PolicyHash)
	}

	// --- Additional per-resource policies (RAM cross-account grants) ---
	p := glue.NewGetResourcePoliciesPaginator(svc, &glue.GetResourcePoliciesInput{})
	for p.HasMorePages() {
		out, e := p.NextPage(ctx, ro)
		if e != nil {
			return s.n - start, e
		}
		for _, gp := range out.GetResourcePoliciesResponseList {
			if gp.PolicyInJson == nil {
				continue
			}
			hash := aws.ToString(gp.PolicyHash)
			if hash != "" && hash == seenHash {
				continue // already emitted as catalog policy above
			}
			// Glue does not surface per-resource ARNs in GetResourcePolicies;
			// use the catalog ARN qualified by hash so each fact has a unique source.
			src := catalogArn
			if hash != "" {
				src = catalogArn + "/policy/" + hash
			}
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				src, "", map[string]any{"policy": aws.ToString(gp.PolicyInJson)})
			if seenHash == "" {
				seenHash = hash // track first seen to avoid re-emitting
			}
		}
	}

	return s.n - start, nil
}
