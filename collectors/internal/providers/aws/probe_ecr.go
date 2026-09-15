package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

func init() {
	registerFetcher("GetRepositoryPolicy", "aws:ecr:repository", fetchEcrGetRepositoryPolicy)
	registerFetcher("ListTagsForResource", "aws:ecr:repository", fetchEcrListTagsForResource)
}

// Exposure probe: aws-ecr-repository-policy-config (GetRepositoryPolicy -> policyText).
func fetchEcrGetRepositoryPolicy(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ecr.NewFromConfig(c.cfg).GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *ecr.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ecr-repository-tags-value-config (ListTagsForResource -> tags[].Value).
func fetchEcrListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ecr.NewFromConfig(c.cfg).ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *ecr.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
