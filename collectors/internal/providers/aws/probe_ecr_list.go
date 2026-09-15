package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func init() {
	registerListFetcher("BatchGetImage", listFetchEcrBatchGetImage)
}

// listFetchEcrBatchGetImage enumerates all ECR repositories in the region, then
// all images per repository, and fetches the full image manifest for each batch
// via BatchGetImage (read-only); per-item errors are skipped. The prober applies
// the site's response_path (images[].imageManifest) to each returned response.
func listFetchEcrBatchGetImage(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := ecr.NewFromConfig(c.cfg)
	ro := func(o *ecr.Options) { o.Region = region }
	var out []any

	// Step 1: enumerate repositories.
	rp := ecr.NewDescribeRepositoriesPaginator(svc, &ecr.DescribeRepositoriesInput{})
	for rp.HasMorePages() {
		rPage, err := rp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, repo := range rPage.Repositories {
			if repo.RepositoryName == nil {
				continue
			}
			repoName := repo.RepositoryName

			// Step 2: enumerate images in the repository to collect image identifiers.
			ip := ecr.NewDescribeImagesPaginator(svc, &ecr.DescribeImagesInput{
				RepositoryName: repoName,
			})
			for ip.HasMorePages() {
				iPage, err := ip.NextPage(ctx, ro)
				if err != nil {
					break // move to next repository on error
				}

				// Build a batch of ImageIdentifiers from this page.
				ids := make([]types.ImageIdentifier, 0, len(iPage.ImageDetails))
				for _, img := range iPage.ImageDetails {
					if img.ImageDigest == nil {
						continue
					}
					ids = append(ids, types.ImageIdentifier{
						ImageDigest: img.ImageDigest,
					})
				}
				if len(ids) == 0 {
					continue
				}

				// Step 3: fetch image manifests for this batch.
				d, e := svc.BatchGetImage(ctx, &ecr.BatchGetImageInput{
					RepositoryName: repoName,
					ImageIds:       ids,
				}, ro)
				if e != nil {
					continue // per-item error — skip
				}
				out = append(out, jsonify(d))
			}
		}
	}
	return out, nil
}
