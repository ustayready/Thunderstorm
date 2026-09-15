package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
)

func init() {
	registerFactCollector("lakeformation-resource-policy", "regional", collectLakeformationPolicies)
}

// collectLakeformationPolicies emits Lake Formation data-lake settings as a
// resource_policy fact (CrossAccountTrust surface).
//
// Lake Formation does not expose a JSON resource policy in the IAM sense.
// Instead it maintains an account-level settings object (GetDataLakeSettings)
// that controls the cross-account grant surface: data-lake administrators,
// trusted resource owners, external-data-filtering allow-list, and the
// CROSS_ACCOUNT_VERSION parameter that governs RAM-based cross-account sharing.
// These settings collectively determine which principals from other accounts can
// be granted permissions via the Lake Formation grant model, making them the
// structural equivalent of a resource-based policy for the Data Catalog.
//
// The resource ARN emitted is the Data Catalog ARN for the region:
//
//	arn:aws:lakeformation:<region>:<account>:catalog
func collectLakeformationPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := lakeformation.NewFromConfig(c.cfg)
	ro := func(o *lakeformation.Options) { o.Region = region }
	start := s.n

	out, err := svc.GetDataLakeSettings(ctx, &lakeformation.GetDataLakeSettingsInput{}, ro)
	if err != nil || out.DataLakeSettings == nil {
		// Service not configured / no settings in this region — not an error.
		return 0, nil
	}

	settings := out.DataLakeSettings

	// Only emit when there is meaningful cross-account configuration: at least one
	// admin, trusted resource owner, external data filtering principal, or an
	// explicit cross-account version parameter.
	hasCrossAccount := len(settings.DataLakeAdmins) > 0 ||
		len(settings.TrustedResourceOwners) > 0 ||
		len(settings.ExternalDataFilteringAllowList) > 0 ||
		len(settings.ReadOnlyAdmins) > 0

	if !hasCrossAccount {
		// Check Parameters for CROSS_ACCOUNT_VERSION key.
		if _, ok := settings.Parameters["CROSS_ACCOUNT_VERSION"]; ok {
			hasCrossAccount = true
		}
	}

	if !hasCrossAccount {
		return 0, nil
	}

	raw, e := json.Marshal(settings)
	if e != nil {
		return 0, fmt.Errorf("lakeformation: marshal DataLakeSettings: %w", e)
	}

	catalogArn := fmt.Sprintf("arn:aws:lakeformation:%s:%s:catalog", region, s.account)
	s.emitFact("resource_policy", "CrossAccountTrust", s.scopeRegion(region),
		catalogArn, "", map[string]any{"policy": string(raw)})

	return s.n - start, nil
}
