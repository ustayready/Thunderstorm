package aws

// Exposure probes for RAM — remaining read_api operations.
// The inventory resource type is aws:ram:resource_share whose native_id /
// arn is the resource share ARN.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ram"
)

func init() {
	registerFetcher("GetPermission", "aws:ram:resource_share", fetchRAMGetPermissionExt)
}

// fetchRAMGetPermissionExt implements the exposure probe
// aws-ram-customer-permission-template-config
// (GetPermission -> permission.permission).
//
// The inventory item is a resource share, not a permission directly, so we
// first enumerate the permissions attached to the share via
// ListResourceSharePermissions and then call GetPermission for each one.
// All permission documents are collected into a top-level "permissions" list
// so the catalog path "permission.permission" resolves against each entry.
func fetchRAMGetPermissionExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	svc := ram.NewFromConfig(c.cfg)
	ro := func(o *ram.Options) { o.Region = region }

	shareArn := itemStr(item, "arn", "native_id")

	// Enumerate all permissions associated with this resource share.
	listOut, err := svc.ListResourceSharePermissions(ctx, &ram.ListResourceSharePermissionsInput{
		ResourceShareArn: aws.String(shareArn),
	}, ro)
	if err != nil {
		return nil, fmt.Errorf("ListResourceSharePermissions(%s): %w", shareArn, err)
	}

	// For each permission, fetch the full permission detail (including the
	// policy document in permission.permission).
	type permDetail struct {
		Permission any `json:"permission"`
	}
	results := make([]permDetail, 0, len(listOut.Permissions))
	for _, p := range listOut.Permissions {
		permArn := aws.ToString(p.Arn)
		if permArn == "" {
			continue
		}
		getOut, err := svc.GetPermission(ctx, &ram.GetPermissionInput{
			PermissionArn: aws.String(permArn),
		}, ro)
		if err != nil {
			// A per-permission error is non-fatal — skip missing/inaccessible entries.
			continue
		}
		results = append(results, permDetail{Permission: jsonify(getOut.Permission)})
	}

	// Return as {permission: <first result>} when there is exactly one, or
	// wrap all results so multi-permission shares are not silently truncated.
	if len(results) == 1 {
		return map[string]any{"permission": results[0].Permission}, nil
	}
	return map[string]any{"permissions": jsonify(results)}, nil
}
