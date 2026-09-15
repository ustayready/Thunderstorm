package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/appmesh"
)

func init() { registerListFetcher("DescribeRoute", listFetchAppmeshDescribeRoute) }

// listFetchAppmeshDescribeRoute enumerates all meshes → virtual routers → routes
// in a region and returns each DescribeRoute detail response (read-only); the
// prober applies the site's response_path to each result.
func listFetchAppmeshDescribeRoute(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := appmesh.NewFromConfig(c.cfg)
	ro := func(o *appmesh.Options) { o.Region = region }
	var out []any

	meshPager := appmesh.NewListMeshesPaginator(svc, &appmesh.ListMeshesInput{})
	for meshPager.HasMorePages() {
		meshPage, err := meshPager.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, mesh := range meshPage.Meshes {
			if mesh.MeshName == nil {
				continue
			}
			vrPager := appmesh.NewListVirtualRoutersPaginator(svc, &appmesh.ListVirtualRoutersInput{
				MeshName: mesh.MeshName,
			})
			for vrPager.HasMorePages() {
				vrPage, err := vrPager.NextPage(ctx, ro)
				if err != nil {
					break
				}
				for _, vr := range vrPage.VirtualRouters {
					if vr.VirtualRouterName == nil {
						continue
					}
					routePager := appmesh.NewListRoutesPaginator(svc, &appmesh.ListRoutesInput{
						MeshName:          mesh.MeshName,
						VirtualRouterName: vr.VirtualRouterName,
					})
					for routePager.HasMorePages() {
						routePage, err := routePager.NextPage(ctx, ro)
						if err != nil {
							break
						}
						for _, route := range routePage.Routes {
							if route.RouteName == nil {
								continue
							}
							d, e := svc.DescribeRoute(ctx, &appmesh.DescribeRouteInput{
								MeshName:          mesh.MeshName,
								VirtualRouterName: vr.VirtualRouterName,
								RouteName:         route.RouteName,
							}, ro)
							if e != nil {
								continue // per-item error (not found / access) — skip
							}
							out = append(out, jsonify(d))
						}
					}
				}
			}
		}
	}
	return out, nil
}
