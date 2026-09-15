package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/detective"
)

func init() { register("detective:ListGraphs", opDetectiveListGraphs) }

// opDetectiveListGraphs enumerates Detective behavior graphs (read-only).
func opDetectiveListGraphs(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := detective.NewFromConfig(c.cfg)
	p := detective.NewListGraphsPaginator(svc, &detective.ListGraphsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *detective.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, g := range out.GraphList {
			recs = append(recs, Record{
				"arn": aws.ToString(g.Arn),
			})
		}
	}
	return recs, nil
}
