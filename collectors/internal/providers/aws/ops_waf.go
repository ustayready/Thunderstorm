package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func init() { register("waf:ListWebACLs", opWAFListWebACLs) }

// opWAFListWebACLs enumerates WAFv2 regional Web ACLs (read-only).
func opWAFListWebACLs(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := wafv2.NewFromConfig(c.cfg)
	var recs []Record
	var nextMarker *string
	for {
		out, err := svc.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope:      types.ScopeRegional,
			Limit:      aws.Int32(100),
			NextMarker: nextMarker,
		}, func(o *wafv2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, acl := range out.WebACLs {
			recs = append(recs, Record{
				"web_acl_id": aws.ToString(acl.Id),
				"arn":        aws.ToString(acl.ARN),
			})
		}
		if out.NextMarker == nil {
			break
		}
		nextMarker = out.NextMarker
	}
	return recs, nil
}
