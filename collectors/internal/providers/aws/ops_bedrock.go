package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
)

func init() { register("bedrock:ListCustomModels", opBedrockListCustomModels) }

// opBedrockListCustomModels enumerates Bedrock custom models (read-only).
func opBedrockListCustomModels(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := bedrock.NewFromConfig(c.cfg)
	p := bedrock.NewListCustomModelsPaginator(svc, &bedrock.ListCustomModelsInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *bedrock.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, m := range out.ModelSummaries {
			recs = append(recs, Record{
				"model_name": aws.ToString(m.ModelName),
				"arn":        aws.ToString(m.ModelArn),
			})
		}
	}
	return recs, nil
}
