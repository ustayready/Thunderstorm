package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
)

func init() { register("codepipeline:ListPipelines", opCodePipelineListPipelines) }

// opCodePipelineListPipelines enumerates CodePipeline pipelines (read-only).
func opCodePipelineListPipelines(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := codepipeline.NewFromConfig(c.cfg)
	p := codepipeline.NewListPipelinesPaginator(svc, &codepipeline.ListPipelinesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *codepipeline.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Pipelines {
			recs = append(recs, Record{
				"pipeline_name": aws.ToString(item.Name),
			})
		}
	}
	return recs, nil
}
