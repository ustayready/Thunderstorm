package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
)

func init() { register("athena:ListWorkGroups", opAthenaListWorkGroups) }

// opAthenaListWorkGroups enumerates Athena workgroups (read-only).
func opAthenaListWorkGroups(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := athena.NewFromConfig(c.cfg)
	p := athena.NewListWorkGroupsPaginator(svc, &athena.ListWorkGroupsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *athena.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, wg := range out.WorkGroups {
			recs = append(recs, Record{
				"workgroup_name": aws.ToString(wg.Name),
			})
		}
	}
	return recs, nil
}
