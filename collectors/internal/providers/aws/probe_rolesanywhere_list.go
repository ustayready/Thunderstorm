package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
)

func init() {
	registerListFetcher("GetProfile", listFetchRolesanywhereGetProfile)
	registerListFetcher("ListTagsForResource", listFetchRolesanywhereListTagsForResource)
}

// listFetchRolesanywhereGetProfile enumerates all Roles Anywhere profiles in a
// region and returns each GetProfile detail response (read-only); the prober
// applies the site's response_path (profile.sessionPolicy) to each.
func listFetchRolesanywhereGetProfile(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := rolesanywhere.NewFromConfig(c.cfg)
	ro := func(o *rolesanywhere.Options) { o.Region = region }
	var out []any
	p := rolesanywhere.NewListProfilesPaginator(svc, &rolesanywhere.ListProfilesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, profile := range page.Profiles {
			d, e := svc.GetProfile(ctx, &rolesanywhere.GetProfileInput{
				ProfileId: profile.ProfileId,
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}
	return out, nil
}

// listFetchRolesanywhereListTagsForResource enumerates all Roles Anywhere trust
// anchors and profiles in a region and returns each ListTagsForResource response
// (read-only); the prober applies the site's response_path (tags[].value) to each.
func listFetchRolesanywhereListTagsForResource(ctx context.Context, c *Client, region string) ([]any, error) {
	svc := rolesanywhere.NewFromConfig(c.cfg)
	ro := func(o *rolesanywhere.Options) { o.Region = region }
	var out []any

	// Enumerate trust anchors.
	tp := rolesanywhere.NewListTrustAnchorsPaginator(svc, &rolesanywhere.ListTrustAnchorsInput{})
	for tp.HasMorePages() {
		page, err := tp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, ta := range page.TrustAnchors {
			d, e := svc.ListTagsForResource(ctx, &rolesanywhere.ListTagsForResourceInput{
				ResourceArn: aws.String(*ta.TrustAnchorArn),
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}

	// Enumerate profiles.
	pp := rolesanywhere.NewListProfilesPaginator(svc, &rolesanywhere.ListProfilesInput{})
	for pp.HasMorePages() {
		page, err := pp.NextPage(ctx, ro)
		if err != nil {
			return out, err
		}
		for _, profile := range page.Profiles {
			d, e := svc.ListTagsForResource(ctx, &rolesanywhere.ListTagsForResourceInput{
				ResourceArn: aws.String(*profile.ProfileArn),
			}, ro)
			if e != nil {
				continue // per-item error (not found / access) — skip
			}
			out = append(out, jsonify(d))
		}
	}

	return out, nil
}
