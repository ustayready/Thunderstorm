package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func init() { registerListFetcher("GetLayerVersion", listFetchLambdaGetLayerVersion) }

// listFetchLambdaGetLayerVersion enumerates all Lambda layers and their versions
// in a region, then fetches each version's detail via GetLayerVersion (read-only).
// The prober applies the site's response_path (Content.Location) to each result.
func listFetchLambdaGetLayerVersion(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := lambda.NewFromConfig(c.cfg)
	ro := func(o *lambda.Options) { o.Region = region }
	var out []any

	lp := lambda.NewListLayersPaginator(svc, &lambda.ListLayersInput{})
	for lp.HasMorePages() {
		layerPage, err := lp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, layer := range layerPage.Layers {
			if layer.LayerName == nil {
				continue
			}
			vp := lambda.NewListLayerVersionsPaginator(svc, &lambda.ListLayerVersionsInput{
				LayerName: layer.LayerName,
			})
			for vp.HasMorePages() {
				verPage, err := vp.NextPage(ctx, ro)
				if err != nil {
					break // per-layer error — skip remaining versions for this layer
				}
				for _, ver := range verPage.LayerVersions {
					d, e := svc.GetLayerVersion(ctx, &lambda.GetLayerVersionInput{
						LayerName:     layer.LayerName,
						VersionNumber: aws.Int64(ver.Version),
					}, ro)
					if e != nil {
						continue // per-version error (not found / access) — skip
					}
					out = append(out, jsonify(d))
				}
			}
		}
	}
	return out, nil
}
