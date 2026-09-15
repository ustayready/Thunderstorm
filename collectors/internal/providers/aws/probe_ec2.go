package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	registerFetcher("DescribeInstanceAttribute", "aws:ec2:instance", fetchEc2DescribeInstanceAttribute)
	registerFetcher("GetConsoleOutput", "aws:ec2:instance", fetchEc2GetConsoleOutput)
	registerFetcher("GetPasswordData", "aws:ec2:instance", fetchEc2GetPasswordData)
	registerFetcher("DescribeTags", "aws:ec2:instance", fetchEc2DescribeTags)
}

// Exposure probe: aws-ec2-instance-user-data-bootstrap (DescribeInstanceAttribute -> UserData.Value).
func fetchEc2DescribeInstanceAttribute(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: aws.String(itemStr(item, "native_id", "arn")),
		Attribute:  types.InstanceAttributeNameUserData,
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ec2-console-output-log (GetConsoleOutput -> Output).
func fetchEc2GetConsoleOutput(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).GetConsoleOutput(ctx, &ec2.GetConsoleOutputInput{
		InstanceId: aws.String(itemStr(item, "native_id", "arn")),
		Latest:     aws.Bool(true),
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ec2-windows-password-data-output (GetPasswordData -> PasswordData).
func fetchEc2GetPasswordData(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).GetPasswordData(ctx, &ec2.GetPasswordDataInput{
		InstanceId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-ec2-resource-tags-value-config (DescribeTags -> Tags[].Value).
func fetchEc2DescribeTags(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := ec2.NewFromConfig(c.cfg).DescribeTags(ctx, &ec2.DescribeTagsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{itemStr(item, "native_id", "arn")},
			},
		},
	}, func(o *ec2.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
