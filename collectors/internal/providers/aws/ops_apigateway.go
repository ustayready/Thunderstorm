package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func init() { register("apigateway:GET", opAPIGatewayGetRestApis) }

// opAPIGatewayGetRestApis enumerates API Gateway REST APIs (read-only).
func opAPIGatewayGetRestApis(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := apigateway.NewFromConfig(c.cfg)
	p := apigateway.NewGetRestApisPaginator(svc, &apigateway.GetRestApisInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *apigateway.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Items {
			id := aws.ToString(item.Id)
			recs = append(recs, Record{
				"rest_api_id": id,
				"arn":         fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, id),
			})
		}
	}
	return recs, nil
}
