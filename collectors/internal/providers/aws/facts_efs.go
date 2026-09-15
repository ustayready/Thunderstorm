package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func init() { registerFactCollector("efs-resource-policy", "regional", collectEfsPolicies) }

// collectEfsPolicies emits EFS file system resource policies as resource_policy
// facts (CrossAccountTrust surface). File systems with no policy are skipped.
func collectEfsPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := efs.NewFromConfig(c.cfg)
	ro := func(o *efs.Options) { o.Region = region }
	scope := s.scopeRegion(region)
	start := s.n

	p := efs.NewDescribeFileSystemsPaginator(svc, &efs.DescribeFileSystemsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, fs := range out.FileSystems {
			pol, e := svc.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
				FileSystemId: fs.FileSystemId,
			}, ro)
			if e != nil || pol.Policy == nil {
				continue // no policy on this file system
			}
			src := firstNonEmpty(aws.ToString(fs.FileSystemArn), aws.ToString(fs.FileSystemId))
			s.emitFact("resource_policy", "CrossAccountTrust", scope,
				src, "", map[string]any{"policy": aws.ToString(pol.Policy)})
		}
	}
	return s.n - start, nil
}
