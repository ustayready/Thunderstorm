package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
)

func init() { register("codeartifact:ListRepositories", opCodeArtifactListRepositories) }

// opCodeArtifactListRepositories enumerates CodeArtifact repositories (read-only).
func opCodeArtifactListRepositories(ctx context.Context, c *Client, region string, _ map[string]string) ([]Record, error) {
	svc := codeartifact.NewFromConfig(c.cfg)
	p := codeartifact.NewListRepositoriesPaginator(svc, &codeartifact.ListRepositoriesInput{})
	var recs []Record
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, func(o *codeartifact.Options) { o.Region = region })
		if err != nil {
			return nil, err
		}
		for _, r := range out.Repositories {
			recs = append(recs, Record{
				"repository_name": aws.ToString(r.Name),
				"arn":             aws.ToString(r.Arn),
			})
		}
	}
	return recs, nil
}
