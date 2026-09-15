package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
)

func init() { register("imagebuilder:ListImagePipelines", opImageBuilderListImagePipelines) }

// opImageBuilderListImagePipelines enumerates EC2 Image Builder pipelines (read-only).
func opImageBuilderListImagePipelines(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := imagebuilder.NewFromConfig(c.cfg)
	p := imagebuilder.NewListImagePipelinesPaginator(svc, &imagebuilder.ListImagePipelinesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *imagebuilder.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.ImagePipelineList {
			recs = append(recs, Record{
				"name": aws.ToString(item.Name),
				"arn":  aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
