package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// collectS3PolicyFacts emits S3 bucket policies as resource_policy facts
// (CrossAccountTrust surface). Buckets are global; each policy is fetched in the
// bucket's own region. A bucket with no policy is skipped (not an error).
func collectS3PolicyFacts(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := s3.NewFromConfig(c.cfg)
	start := s.n
	out, err := svc.ListBuckets(ctx, &s3.ListBucketsInput{}, func(o *s3.Options) { o.Region = region })
	if err != nil {
		return 0, err
	}
	for _, bkt := range out.Buckets {
		name := aws.ToString(bkt.Name)
		bregion := region
		if loc, e := svc.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bkt.Name},
			func(o *s3.Options) { o.Region = region }); e == nil && string(loc.LocationConstraint) != "" {
			bregion = string(loc.LocationConstraint)
		}
		pol, e := svc.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: bkt.Name},
			func(o *s3.Options) { o.Region = bregion })
		if e != nil || pol.Policy == nil { // no policy / access → skip
			continue
		}
		s.emitFact("resource_policy", "CrossAccountTrust", s.scopeRegion(bregion),
			"arn:aws:s3:::"+name, "", map[string]any{"policy": aws.ToString(pol.Policy)})
	}
	return s.n - start, nil
}

// collectKMSPolicyFacts emits KMS key policies as resource_policy facts.
func collectKMSPolicyFacts(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := kms.NewFromConfig(c.cfg)
	ro := func(o *kms.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n
	p := kms.NewListKeysPaginator(svc, &kms.ListKeysInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, k := range out.Keys {
			pol, e := svc.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId: k.KeyId, PolicyName: aws.String("default"),
			}, ro)
			if e != nil || pol.Policy == nil {
				continue
			}
			src := firstNonEmpty(aws.ToString(k.KeyArn), aws.ToString(k.KeyId))
			s.emitFact("resource_policy", "CrossAccountTrust", scope, src, "",
				map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
