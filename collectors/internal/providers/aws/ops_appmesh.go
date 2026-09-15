package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
)

func init() { register("appmesh:ListMeshes", opAppMeshListMeshes) }

// opAppMeshListMeshes enumerates App Mesh meshes (read-only).
func opAppMeshListMeshes(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := appmesh.NewFromConfig(c.cfg)
	p := appmesh.NewListMeshesPaginator(svc, &appmesh.ListMeshesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *appmesh.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, item := range out.Meshes {
			recs = append(recs, Record{
				"mesh_name": aws.ToString(item.MeshName),
				"arn":       aws.ToString(item.Arn),
			})
		}
	}
	return recs, nil
}
