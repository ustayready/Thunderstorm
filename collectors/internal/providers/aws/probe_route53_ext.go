package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func init() {
	registerFetcher("ListTagsForResource", "aws:route53:hosted_zone", fetchRoute53ListTagsForResourceExt)
	registerFetcher("GetHostedZone", "aws:route53:hosted_zone", fetchRoute53GetHostedZoneExt)
	registerFetcher("GetDNSSEC", "aws:route53:hosted_zone", fetchRoute53GetDNSSECExt)
	registerFetcher("ListQueryLoggingConfigs", "aws:route53:hosted_zone", fetchRoute53ListQueryLoggingConfigsExt)
	registerFetcher("ListVPCAssociationAuthorizations", "aws:route53:hosted_zone", fetchRoute53ListVPCAssociationAuthorizationsExt)
	registerFetcher("ListTrafficPolicyInstancesByHostedZone", "aws:route53:hosted_zone", fetchRoute53ListTrafficPolicyInstancesByHostedZoneExt)
}

// fetchRoute53ListTagsForResourceExt fetches tag values for a hosted zone
// (exposure site: aws-route53-hosted-zone-tags-value-config).
// Response path: ResourceTagSet.Tags[].Value
func fetchRoute53ListTagsForResourceExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).ListTagsForResource(ctx, &route53.ListTagsForResourceInput{
		ResourceType: types.TagResourceTypeHostedzone,
		ResourceId:   aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRoute53GetHostedZoneExt fetches full hosted-zone config including
// associated VPCs (for private zones) and delegation set.
// Response path: HostedZone.Config.Comment / DelegationSet.NameServers[] / VPCs[].VPCId
func fetchRoute53GetHostedZoneExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).GetHostedZone(ctx, &route53.GetHostedZoneInput{
		Id: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRoute53GetDNSSECExt fetches DNSSEC key-signing key (KSK) details for a
// hosted zone. KSK records include the public key, DS record, and signing algorithm —
// useful for detecting key material exposure.
// Response path: KeySigningKeys[].PublicKey / KeySigningKeys[].DSRecord
func fetchRoute53GetDNSSECExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).GetDNSSEC(ctx, &route53.GetDNSSECInput{
		HostedZoneId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRoute53ListQueryLoggingConfigsExt lists DNS query logging configurations
// for a hosted zone. The CloudWatchLogsLogGroupArn reveals where query logs are
// written — logs can contain sensitive hostnames / credential fragments.
// Response path: QueryLoggingConfigs[].CloudWatchLogsLogGroupArn
func fetchRoute53ListQueryLoggingConfigsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{
		HostedZoneId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRoute53ListVPCAssociationAuthorizationsExt lists VPCs from other accounts
// that are authorized to associate with this private hosted zone.
// Response path: VPCs[].VPCId / VPCs[].VPCRegion
func fetchRoute53ListVPCAssociationAuthorizationsExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).ListVPCAssociationAuthorizations(ctx, &route53.ListVPCAssociationAuthorizationsInput{
		HostedZoneId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}

// fetchRoute53ListTrafficPolicyInstancesByHostedZoneExt lists traffic policy
// instances attached to a hosted zone. Instances reference traffic-policy
// documents that may contain internal routing configuration.
// Response path: TrafficPolicyInstances[].TrafficPolicyId / [].TrafficPolicyVersion
func fetchRoute53ListTrafficPolicyInstancesByHostedZoneExt(ctx context.Context, c *Client, region string, item map[string]any) (any, error) {
	out, err := route53.NewFromConfig(c.cfg).ListTrafficPolicyInstancesByHostedZone(ctx, &route53.ListTrafficPolicyInstancesByHostedZoneInput{
		HostedZoneId: aws.String(itemStr(item, "native_id", "arn")),
	}, func(o *route53.Options) { o.Region = region })
	if err != nil {
		return nil, err
	}
	return jsonify(out), nil
}
