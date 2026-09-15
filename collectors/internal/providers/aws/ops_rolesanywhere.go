package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
)

func init() { register("rolesanywhere:ListTrustAnchors", opRolesAnywherListTrustAnchors) }

// opRolesAnywherListTrustAnchors enumerates IAM Roles Anywhere trust anchors (read-only).
func opRolesAnywherListTrustAnchors(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := rolesanywhere.NewFromConfig(c.cfg)
	p := rolesanywhere.NewListTrustAnchorsPaginator(svc, &rolesanywhere.ListTrustAnchorsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *rolesanywhere.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.TrustAnchors {
			recs = append(recs, Record{
				"trust_anchor_id":  aws.ToString(item.TrustAnchorId),
				"trust_anchor_arn": aws.ToString(item.TrustAnchorArn),
			})
		}
	}
	return recs, nil
}
