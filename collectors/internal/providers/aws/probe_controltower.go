package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
)

func init() {
	registerFetcher("GetLandingZone", "aws:controltower:landing_zone", fetchControlTowerGetLandingZone)
	registerFetcher("ListTagsForResource", "aws:controltower:landing_zone", fetchControlTowerListTagsForResource)
}

// Exposure probe: aws-controltower-landing-zone-manifest-config (GetLandingZone -> landingZone.manifest).
func fetchControlTowerGetLandingZone(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := controltower.NewFromConfig(c.cfg).GetLandingZone(ctx, &controltower.GetLandingZoneInput{
		LandingZoneIdentifier: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *controltower.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// Exposure probe: aws-controltower-resource-tags-value-config (ListTagsForResource -> tags.<value>).
func fetchControlTowerListTagsForResource(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := controltower.NewFromConfig(c.cfg).ListTagsForResource(ctx, &controltower.ListTagsForResourceInput{
		ResourceArn: aws.String(itemStr(item, "arn", "native_id")),
	}, func(o *controltower.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
