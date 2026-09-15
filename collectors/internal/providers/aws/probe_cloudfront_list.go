package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func init() {
	registerListFetcher("GetFunction", listFetchCloudfrontGetFunction)
}

// listFetchCloudfrontGetFunction enumerates all CloudFront Functions in the
// account (DEVELOPMENT stage, which includes the function code) and returns
// each GetFunction response as a jsonified value. The prober applies the
// site's response_path (FunctionCode) to each result.
//
// ListFunctions has no SDK paginator; pagination is done manually via
// FunctionList.NextMarker.
func listFetchCloudfrontGetFunction(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := cloudfront.NewFromConfig(c.cfg)
	ro := func(o *cloudfront.Options) { o.Region = region }

	var (
		out    []any
		marker *string
	)
	for {
		page, err := svc.ListFunctions(ctx, &cloudfront.ListFunctionsInput{
			Marker: marker,
			// Return functions in both stages so we capture all code artifacts;
			// the site definition targets DEVELOPMENT but we fetch each name at
			// DEVELOPMENT stage regardless of the summary's reported stage.
		}, ro)
		if err != nil {
			return out, err
		}
		if page.FunctionList == nil {
			break
		}
		for _, fn := range page.FunctionList.Items {
			if fn.Name == nil {
				continue
			}
			d, e := svc.GetFunction(ctx, &cloudfront.GetFunctionInput{
				Name:  aws.String(*fn.Name),
				Stage: types.FunctionStageDevelopment,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access denied) — skip
			}
			out = append(out, jsonify(d))
		}
		if page.FunctionList.NextMarker == nil || *page.FunctionList.NextMarker == "" {
			break
		}
		marker = page.FunctionList.NextMarker
	}
	return out, nil
}
