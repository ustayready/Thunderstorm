package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
)

func init() { register("inspector:ListFindings", opInspectorListFindings) }

// opInspectorListFindings enumerates Inspector v2 findings (read-only).
func opInspectorListFindings(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := inspector2.NewFromConfig(c.cfg)
	p := inspector2.NewListFindingsPaginator(svc, &inspector2.ListFindingsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *inspector2.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, f := range out.Findings {
			recs = append(recs, Record{
				"finding_arn": aws.ToString(f.FindingArn),
			})
		}
	}
	return recs, nil
}
