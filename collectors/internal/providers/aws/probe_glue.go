package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
)

func init() {
	registerFetcher("GetJob", "aws:glue:job", fetchGlueGetJob)
	registerFetcher("GetTags", "aws:glue:job", fetchGlueGetTags)
}

// Exposure probe: aws-glue-job-default-arguments (GetJob -> Job.{DefaultArguments,NonOverridableArguments}).
func fetchGlueGetJob(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := glue.NewFromConfig(c.cfg).GetJob(ctx, &glue.GetJobInput{
		JobName: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *glue.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-glue-resource-tags-value-config (GetTags -> Tags.<value>).
func fetchGlueGetTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := glue.NewFromConfig(c.cfg).GetTags(ctx, &glue.GetTagsInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *glue.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
