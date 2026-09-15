package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() { registerFactCollector("iam-resource-policy", "global", collectIamPolicies) }

// collectIamPolicies emits the document of every ATTACHED managed policy —
// AWS-managed (arn:aws:iam::aws:policy/...) AND customer-managed — as a
// managed_policy fact. This is essential: admins/power-users get their rights
// from AWS-managed policies (AdministratorAccess, *FullAccess), so collecting
// only customer-managed docs left those principals with no resolvable permissions
// and therefore no attack edges. GetPolicyVersion works for both scopes.
func collectIamPolicies(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := iam.NewFromConfig(c.cfg)
	ro := func(o *iam.Options) { o.Region = region }
	start := s.n

	attached := map[string]bool{}     // attached managed policy ARNs
	boundaries := map[string]string{} // principal ARN -> permission-boundary ARN
	add := func(list []iamtypes.AttachedPolicy) {
		for _, ap := range list {
			if ap.PolicyArn != nil {
				attached[aws.ToString(ap.PolicyArn)] = true
			}
		}
	}

	// A list error here must NOT abort the whole collection: users, roles, and
	// groups are independent, and losing one (e.g. throttled ListUsers) must not
	// drop the group's AdministratorAccess and leave every admin looking powerless.
	// Track the failure, collect everything reachable, and surface it at the end.
	var listErr error

	// Discover attached policies + permission boundaries across users, roles, groups.
	// PermissionsBoundary is NOT returned by ListUsers/ListRoles — GetUser/GetRole
	// are required. The boundary CLIPS effective permissions (identity AND boundary
	// must allow); omitting it made broad-but-boundaried identities (e.g. read-only
	// creds with an s3:* policy under a read-only boundary) look far over-permissioned.
	up := iam.NewListUsersPaginator(svc, &iam.ListUsersInput{})
	for up.HasMorePages() {
		out, err := up.NextPage(ctx, ro)
		if err != nil {
			listErr = err
			break
		}
		for _, u := range out.Users {
			p := iam.NewListAttachedUserPoliciesPaginator(svc, &iam.ListAttachedUserPoliciesInput{UserName: u.UserName})
			for p.HasMorePages() {
				o, e := p.NextPage(ctx, ro)
				if e != nil {
					break
				}
				add(o.AttachedPolicies)
			}
			if gu, e := svc.GetUser(ctx, &iam.GetUserInput{UserName: u.UserName}, ro); e == nil &&
				gu.User != nil && gu.User.PermissionsBoundary != nil {
				if b := aws.ToString(gu.User.PermissionsBoundary.PermissionsBoundaryArn); b != "" {
					boundaries[aws.ToString(u.Arn)] = b
					attached[b] = true
				}
			}
		}
	}
	rp := iam.NewListRolesPaginator(svc, &iam.ListRolesInput{})
	for rp.HasMorePages() {
		out, err := rp.NextPage(ctx, ro)
		if err != nil {
			listErr = err
			break
		}
		for _, r := range out.Roles {
			p := iam.NewListAttachedRolePoliciesPaginator(svc, &iam.ListAttachedRolePoliciesInput{RoleName: r.RoleName})
			for p.HasMorePages() {
				o, e := p.NextPage(ctx, ro)
				if e != nil {
					break
				}
				add(o.AttachedPolicies)
			}
			// Role objects from ListRoles include PermissionsBoundary when present.
			if r.PermissionsBoundary != nil {
				if b := aws.ToString(r.PermissionsBoundary.PermissionsBoundaryArn); b != "" {
					boundaries[aws.ToString(r.Arn)] = b
					attached[b] = true
				}
			}
		}
	}
	grp := iam.NewListGroupsPaginator(svc, &iam.ListGroupsInput{})
	for grp.HasMorePages() {
		out, err := grp.NextPage(ctx, ro)
		if err != nil {
			listErr = err
			break
		}
		for _, g := range out.Groups {
			p := iam.NewListAttachedGroupPoliciesPaginator(svc, &iam.ListAttachedGroupPoliciesInput{GroupName: g.GroupName})
			for p.HasMorePages() {
				o, e := p.NextPage(ctx, ro)
				if e != nil {
					break
				}
				add(o.AttachedPolicies)
			}
		}
	}

	// Fetch the active document for each distinct policy (attached + boundaries).
	// A dropped document here is serious: missing AdministratorAccess makes an
	// admin look powerless. Track drops and surface them as a task error rather
	// than silently producing a graph that looks complete but isn't.
	docByArn := map[string]string{}
	var dropped, lastErr = 0, error(nil)
	for arn := range attached {
		pol, err := svc.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)}, ro)
		if err != nil || pol.Policy == nil || pol.Policy.DefaultVersionId == nil {
			if err != nil {
				dropped, lastErr = dropped+1, err
			}
			continue
		}
		ver, e := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(arn), VersionId: pol.Policy.DefaultVersionId,
		}, ro)
		if e != nil || ver.PolicyVersion == nil || ver.PolicyVersion.Document == nil {
			if e != nil {
				dropped, lastErr = dropped+1, e
			}
			continue
		}
		docByArn[arn] = urlDecode(aws.ToString(ver.PolicyVersion.Document))
	}

	// Emit managed-policy documents (the identity's grants).
	for arn, doc := range docByArn {
		s.emitFact("managed_policy", "HasPermission", s.scopeGlobal(), arn, "",
			map[string]any{"document": doc})
	}
	// Emit permission-boundary docs bound to their principal — the engine intersects
	// these with the identity policy so effective permissions are accurate.
	for principal, bArn := range boundaries {
		if doc := docByArn[bArn]; doc != "" {
			s.emitFact("permission_boundary", "PermissionBoundary", s.scopeGlobal(), principal, "",
				map[string]any{"document": doc})
		}
	}
	if listErr != nil {
		return s.n - start, fmt.Errorf("IAM listing was throttled/interrupted (%w) — some principals' managed policies are missing; re-run or lower --concurrency", listErr)
	}
	if dropped > 0 {
		return s.n - start, fmt.Errorf("dropped %d/%d managed-policy documents (last: %w) — effective permissions may be incomplete; re-run or lower --concurrency",
			dropped, len(attached), lastErr)
	}
	return s.n - start, nil
}

// collectIAMFacts emits the identity-graph facts: attached/inline policies
// (HasPolicy / HasPermission), group memberships (MemberOf), and role trust
// policies (CanAssume — also the CrossAccountTrust surface). IAM is global.
func collectIAMFacts(ctx context.Context, c *Client, region string, s *factSink) (int, error) {
	svc := iam.NewFromConfig(c.cfg)
	ro := func(o *iam.Options) { o.Region = region }
	start := s.n

	// --- Users ---
	up := iam.NewListUsersPaginator(svc, &iam.ListUsersInput{})
	for up.HasMorePages() {
		out, err := up.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, u := range out.Users {
			arn := aws.ToString(u.Arn)
			s.attachedPolicies(ctx, svc, ro, arn, "user", u.UserName)
			s.inlineUserPolicies(ctx, svc, ro, arn, u.UserName)
			gp := iam.NewListGroupsForUserPaginator(svc, &iam.ListGroupsForUserInput{UserName: u.UserName})
			for gp.HasMorePages() {
				go2, e := gp.NextPage(ctx, ro)
				if e != nil {
					break
				}
				for _, g := range go2.Groups {
					s.emitFact("membership", "MemberOf", s.scopeGlobal(), arn, aws.ToString(g.Arn), nil)
				}
			}
		}
	}

	// --- Roles (trust + policies) ---
	rp := iam.NewListRolesPaginator(svc, &iam.ListRolesInput{})
	for rp.HasMorePages() {
		out, err := rp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, r := range out.Roles {
			arn := aws.ToString(r.Arn)
			if r.AssumeRolePolicyDocument != nil {
				s.emitFact("trust_policy", "CanAssume", s.scopeGlobal(), arn, "",
					map[string]any{"document": urlDecode(aws.ToString(r.AssumeRolePolicyDocument))})
			}
			s.attachedRolePolicies(ctx, svc, ro, arn, r.RoleName)
			s.inlineRolePolicies(ctx, svc, ro, arn, r.RoleName)
		}
	}

	// --- Groups (policies drive members' effective permissions) ---
	grp := iam.NewListGroupsPaginator(svc, &iam.ListGroupsInput{})
	for grp.HasMorePages() {
		out, err := grp.NextPage(ctx, ro)
		if err != nil {
			return s.n - start, err
		}
		for _, g := range out.Groups {
			arn := aws.ToString(g.Arn)
			s.attachedGroupPolicies(ctx, svc, ro, arn, g.GroupName)
			s.inlineGroupPolicies(ctx, svc, ro, arn, g.GroupName)
		}
	}
	return s.n - start, nil
}

func (s *factSink) attachedPolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn, _ string, user *string) {
	p := iam.NewListAttachedUserPoliciesPaginator(svc, &iam.ListAttachedUserPoliciesInput{UserName: user})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, ap := range o.AttachedPolicies {
			s.emitFact("membership", "HasPolicy", s.scopeGlobal(), arn, aws.ToString(ap.PolicyArn), nil)
		}
	}
}

func (s *factSink) inlineUserPolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn string, user *string) {
	p := iam.NewListUserPoliciesPaginator(svc, &iam.ListUserPoliciesInput{UserName: user})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, name := range o.PolicyNames {
			name := name
			d, e2 := svc.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: user, PolicyName: &name}, ro)
			if e2 == nil {
				s.emitFact("identity_policy", "HasPermission", s.scopeGlobal(), arn, name,
					map[string]any{"document": urlDecode(aws.ToString(d.PolicyDocument))})
			}
		}
	}
}

func (s *factSink) attachedRolePolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn string, role *string) {
	p := iam.NewListAttachedRolePoliciesPaginator(svc, &iam.ListAttachedRolePoliciesInput{RoleName: role})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, ap := range o.AttachedPolicies {
			s.emitFact("membership", "HasPolicy", s.scopeGlobal(), arn, aws.ToString(ap.PolicyArn), nil)
		}
	}
}

func (s *factSink) inlineRolePolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn string, role *string) {
	p := iam.NewListRolePoliciesPaginator(svc, &iam.ListRolePoliciesInput{RoleName: role})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, name := range o.PolicyNames {
			name := name
			d, e2 := svc.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: role, PolicyName: &name}, ro)
			if e2 == nil {
				s.emitFact("identity_policy", "HasPermission", s.scopeGlobal(), arn, name,
					map[string]any{"document": urlDecode(aws.ToString(d.PolicyDocument))})
			}
		}
	}
}

func (s *factSink) attachedGroupPolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn string, group *string) {
	p := iam.NewListAttachedGroupPoliciesPaginator(svc, &iam.ListAttachedGroupPoliciesInput{GroupName: group})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, ap := range o.AttachedPolicies {
			s.emitFact("membership", "HasPolicy", s.scopeGlobal(), arn, aws.ToString(ap.PolicyArn), nil)
		}
	}
}

func (s *factSink) inlineGroupPolicies(ctx context.Context, svc *iam.Client, ro func(*iam.Options), arn string, group *string) {
	p := iam.NewListGroupPoliciesPaginator(svc, &iam.ListGroupPoliciesInput{GroupName: group})
	for p.HasMorePages() {
		o, e := p.NextPage(ctx, ro)
		if e != nil {
			return
		}
		for _, name := range o.PolicyNames {
			name := name
			d, e2 := svc.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: group, PolicyName: &name}, ro)
			if e2 == nil {
				s.emitFact("identity_policy", "HasPermission", s.scopeGlobal(), arn, name,
					map[string]any{"document": urlDecode(aws.ToString(d.PolicyDocument))})
			}
		}
	}
}
