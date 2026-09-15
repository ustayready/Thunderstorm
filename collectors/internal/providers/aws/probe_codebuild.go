package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/codebuild"
)

func init() {
	registerFetcher("BatchGetProjects", "aws:codebuild:project", fetchCodeBuildBatchGetProjects)
}

// Exposure probe: aws-codebuild-project-plaintext-environment-value,
// aws-codebuild-project-inline-buildspec, aws-codebuild-resource-tags-value-config
// (BatchGetProjects -> projects[]).
func fetchCodeBuildBatchGetProjects(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := codebuild.NewFromConfig(c.cfg).BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
		Names: []string{itemStr(item, "native_id", "arn")},
	}, func(o *codebuild.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
