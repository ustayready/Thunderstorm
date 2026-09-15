package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datapipeline"
)

func init() { register("datapipeline:ListPipelines", opDataPipelineListPipelines) }

// opDataPipelineListPipelines enumerates AWS Data Pipeline pipelines (read-only).
func opDataPipelineListPipelines(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := datapipeline.NewFromConfig(c.cfg)
	p := datapipeline.NewListPipelinesPaginator(svc, &datapipeline.ListPipelinesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *datapipeline.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.PipelineIdList {
			recs = append(recs, Record{
				"pipeline_id":   aws.ToString(item.Id),
				"pipeline_name": aws.ToString(item.Name),
			})
		}
	}
	return recs, nil
}
