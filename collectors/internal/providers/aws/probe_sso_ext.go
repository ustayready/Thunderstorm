package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

func init() {
	registerFetcher("GetInlinePolicyForPermissionSet", "aws:sso:instance", fetchSSOGetInlinePolicyForPermissionSetExt)
}

// fetchSSOGetInlinePolicyForPermissionSetExt implements the exposure probe for
// aws-sso-permission-set-inline-policy (GetInlinePolicyForPermissionSet -> InlinePolicy).
//
// GetInlinePolicyForPermissionSet requires both InstanceArn and PermissionSetArn.
// The manifest only enumerates aws:sso:instance resources, so PermissionSetArn is
// not present in the inventory item. We enumerate permission sets via
// ListPermissionSets(InstanceArn) and call GetInlinePolicyForPermissionSet for
// each, returning all results as a slice so the prober can walk each one.
func fetchSSOGetInlinePolicyForPermissionSetExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	instanceArn := itemStr(item, "native_id", "arn")
	svc := ssoadmin.NewFromConfig(c.cfg)
	optFn := func(o *ssoadmin.Options) { o.Region = region }

	// Enumerate all permission sets for this instance.
	var permissionSetARNs []string
	var nextToken *string
	for {
		listOut, err := svc.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: aws.String(instanceArn),
			NextToken:   nextToken,
		}, optFn)
		if err != nil {
			return nil, fmt.Errorf("ListPermissionSets: %w", err)
		}
		permissionSetARNs = append(permissionSetARNs, listOut.PermissionSets...)
		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}

	// Fetch the inline policy for each permission set and collect results.
	var results []any
	for _, psARN := range permissionSetARNs {
		psARN := psARN
		out, err := svc.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{
			InstanceArn:      aws.String(instanceArn),
			PermissionSetArn: aws.String(psARN),
		}, optFn)
		if err != nil {
			// A permission set disappearing mid-scan is expected; skip it.
			continue
		}
		results = append(results, jsonify(out))
	}
	return results, nil
}
