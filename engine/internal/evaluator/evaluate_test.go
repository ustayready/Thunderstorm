package evaluator

import (
	"testing"

	"thunderstorm/engine/internal/model"
)

// helpers to build policy facts
func managed(arn, doc string) model.Fact {
	return model.Fact{Kind: "managed_policy", EdgeHint: "HasPermission", Source: arn,
		Attributes: map[string]any{"document": doc}}
}
func attach(principal, polArn string) model.Fact {
	return model.Fact{Kind: "membership", EdgeHint: "HasPolicy", Source: principal, Target: polArn}
}
func inline(principal, doc string) model.Fact {
	return model.Fact{Kind: "identity_policy", Source: principal, Attributes: map[string]any{"document": doc}}
}
func resPolicy(resArn, doc string) model.Fact {
	return model.Fact{Kind: "resource_policy", Source: resArn, Attributes: map[string]any{"policy": doc}}
}
func scp(account, doc string) model.Fact {
	return model.Fact{Kind: "scp", Source: "arn:scp", Scope: model.Scope{Account: account},
		Attributes: map[string]any{"document": doc}}
}

const allowSecretDoc = `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`

func TestIdentityAllowViaAttachedManaged(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/alice"
	s := NewStore([]model.Fact{
		managed("arn:aws:iam::111111111111:policy/read", allowSecretDoc),
		attach(p, "arn:aws:iam::111111111111:policy/read"),
	})
	d := s.Evaluate(p, "secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111111111111:secret:db")
	if !d.Allowed || d.Conditional {
		t.Fatalf("want solid allow, got %+v", d)
	}
	if d.Via != "identity" {
		t.Errorf("via = %q want identity", d.Via)
	}
}

func TestExplicitDenyWins(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/alice"
	deny := `{"Statement":[{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	s := NewStore([]model.Fact{
		inline(p, allowSecretDoc),
		inline(p, deny),
	})
	if d := s.Evaluate(p, "secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111111111111:secret:db"); d.Allowed {
		t.Errorf("explicit deny must win, got allowed")
	}
}

func TestSCPBlocks(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/alice"
	limitedSCP := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	s := NewStore([]model.Fact{
		inline(p, allowSecretDoc),       // identity allows secrets
		scp("111111111111", limitedSCP), // but SCP only allows s3
	})
	if d := s.Evaluate(p, "secretsmanager:GetSecretValue", "arn:secret"); d.Allowed {
		t.Errorf("SCP must block action outside its allow set, got allowed")
	}
	// s3 within SCP still allowed
	s3doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	s2 := NewStore([]model.Fact{inline(p, s3doc), scp("111111111111", limitedSCP)})
	if d := s2.Evaluate(p, "s3:GetObject", "arn:aws:s3:::b/x"); !d.Allowed {
		t.Errorf("action within SCP allow set should pass, got %+v", d)
	}
}

func TestCrossAccountRequiresBothSides(t *testing.T) {
	p := "arn:aws:iam::222222222222:role/reader" // account 222
	res := "arn:aws:s3:::shared/obj"             // bucket owned by 111 (via resource policy account)
	idAllow := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	// resource policy in owner account granting the 222 role
	rp := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}]}`

	// identity-only (no resource grant): cross-account should DENY
	sIdOnly := NewStore([]model.Fact{inline(p, idAllow)})
	if d := sIdOnly.Evaluate(p, "s3:GetObject", res); d.Allowed {
		// resource arn has no account (s3), so AccountOf(res)=="" -> treated same-account.
		// Guard the test against that by using an arn WITH an account below.
		_ = d
	}

	// Use a resource ARN that carries an account (lambda) to exercise cross-account.
	lamRes := "arn:aws:lambda:us-east-1:111111111111:function:fn"
	lamId := `{"Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}`
	lamRP := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/reader"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`

	// identity-only across accounts -> DENY (needs both)
	s1 := NewStore([]model.Fact{inline(p, lamId)})
	if d := s1.Evaluate(p, "lambda:InvokeFunction", lamRes); d.Allowed {
		t.Errorf("cross-account identity-only must be denied, got allowed")
	}
	// both sides -> ALLOW
	s2 := NewStore([]model.Fact{inline(p, lamId), resPolicy(lamRes, lamRP)})
	if d := s2.Evaluate(p, "lambda:InvokeFunction", lamRes); !d.Allowed {
		t.Errorf("cross-account with both sides must allow, got %+v", d)
	}
	_ = rp
}

func TestSameAccountResourceOnlyAllows(t *testing.T) {
	// same-account: a resource policy alone can grant (identity OR resource).
	p := "arn:aws:iam::111111111111:role/app"
	res := "arn:aws:lambda:us-east-1:111111111111:function:fn"
	rp := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	s := NewStore([]model.Fact{resPolicy(res, rp)})
	if d := s.Evaluate(p, "lambda:InvokeFunction", res); !d.Allowed || d.Via != "resource" {
		t.Errorf("same-account resource-only should allow via resource, got %+v", d)
	}
}

func TestConditionalWhenRequestTimeConditionUnresolved(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/alice"
	doc := `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`
	s := NewStore([]model.Fact{inline(p, doc)})
	d := s.Evaluate(p, "secretsmanager:GetSecretValue", "arn:secret")
	if !d.Allowed {
		t.Fatalf("conditional allow should still be Allowed=true, got %+v", d)
	}
	if !d.Conditional {
		t.Errorf("request-time condition should mark Conditional, got %+v", d)
	}
	if len(d.Conditions) == 0 {
		t.Errorf("expected recorded unresolved conditions")
	}
}

// KMS dual-authorization: the KEY POLICY must authorize, not just IAM. A grant
// gated by kms:ViaService is service-mediated and must NOT create a direct
// CanDecrypt — even when the identity policy allows kms:Decrypt. This is the fix
// for admins/read-only users appearing able to decrypt every service-managed key.
func TestKMSViaServiceIsNotDirectDecrypt(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/readonly"
	key := "arn:aws:kms:us-east-1:111111111111:key/abc"
	viaService := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["kms:Decrypt"],"Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"secretsmanager.us-east-1.amazonaws.com","kms:CallerAccount":"111111111111"}}}]}`
	idKms := `{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}`
	// identity allows kms:Decrypt, but the key only grants via SecretsManager -> DENY.
	s := NewStore([]model.Fact{inline(p, idKms), resPolicy(key, viaService)})
	if d := s.Evaluate(p, "kms:Decrypt", key); d.Allowed {
		t.Errorf("ViaService-only key grant must NOT be a direct CanDecrypt, got allowed %+v", d)
	}
}

// Default key policy delegates to IAM via account-root; identity kms:Decrypt then
// genuinely works -> ACTIVE allow.
func TestKMSRootDelegationPlusIdentity(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/dev"
	key := "arn:aws:kms:us-east-1:111111111111:key/abc"
	rootDelegation := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}`
	idKms := `{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}`
	s := NewStore([]model.Fact{inline(p, idKms), resPolicy(key, rootDelegation)})
	if d := s.Evaluate(p, "kms:Decrypt", key); !d.Allowed {
		t.Errorf("root-delegation key + identity kms:Decrypt should allow, got %+v", d)
	}
	// Without the identity grant, root delegation alone is not enough.
	s2 := NewStore([]model.Fact{resPolicy(key, rootDelegation)})
	if d := s2.Evaluate(p, "kms:Decrypt", key); d.Allowed {
		t.Errorf("root delegation without an identity grant must deny, got allowed")
	}
}

// A key policy naming the principal directly (no ViaService) grants access.
func TestKMSDirectKeyPolicyGrant(t *testing.T) {
	p := "arn:aws:iam::111111111111:role/decryptor"
	key := "arn:aws:kms:us-east-1:111111111111:key/abc"
	direct := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/decryptor"},"Action":"kms:Decrypt","Resource":"*"}]}`
	s := NewStore([]model.Fact{resPolicy(key, direct)})
	if d := s.Evaluate(p, "kms:Decrypt", key); !d.Allowed || d.Via != "resource" {
		t.Errorf("direct key-policy grant should allow via resource, got %+v", d)
	}
}

// A resource policy granting Principal: <account>:root is DELEGATION to IAM, not a
// direct grant. Regression: a bucket policy with "root full access" made every
// same-account identity look able to s3:PutBucketPolicy (CanModify/CanControl),
// which AWS returns as implicitDeny unless the identity itself allows it.
func TestResourceRootDelegationIsNotDirectGrant(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/readonly"
	bucket := "arn:aws:s3:::acme-data"
	bp := `{"Statement":[
	  {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:*","Resource":["arn:aws:s3:::acme-data","arn:aws:s3:::acme-data/*"]},
	  {"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::acme-data"}]}`
	s := NewStore([]model.Fact{resPolicy(bucket, bp)})
	if d := s.Evaluate(p, "s3:PutBucketPolicy", bucket); d.Allowed {
		t.Errorf("root delegation must NOT grant PutBucketPolicy without an identity grant, got %+v", d)
	}
	// the public statement genuinely grants ListBucket to everyone
	if d := s.Evaluate(p, "s3:ListBucket", bucket); !d.Allowed {
		t.Errorf("public ListBucket should be allowed, got %+v", d)
	}
	// with an identity grant, it works (delegation + identity)
	s2 := NewStore([]model.Fact{resPolicy(bucket, bp),
		inline(p, `{"Statement":[{"Effect":"Allow","Action":"s3:PutBucketPolicy","Resource":"*"}]}`)})
	if d := s2.Evaluate(p, "s3:PutBucketPolicy", bucket); !d.Allowed {
		t.Errorf("identity grant should allow PutBucketPolicy, got %+v", d)
	}
}

// The near-ubiquitous "deny everything unless MFA is present" statement
// (Deny NotAction:[self-service] Resource:* Condition BoolIfExists
// aws:MultiFactorAuthPresent:false) must NOT hard-deny an admin's entire
// permission set. MFA is a request-time key we can't resolve statically, so the
// access is CONDITIONAL, not absent. Regression for the aws-admins "Can do (0)" bug.
func TestMFADenyIsConditionalNotHardDeny(t *testing.T) {
	p := "arn:aws:iam::111111111111:user/mike.felch"
	admin := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	mfaDeny := `{"Statement":[{"Effect":"Deny","NotAction":["iam:ChangePassword","iam:GetUser"],"Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	s := NewStore([]model.Fact{inline(p, admin), inline(p, mfaDeny)})
	d := s.Evaluate(p, "s3:GetObject", "arn:aws:s3:::bucket/obj")
	if !d.Allowed {
		t.Fatalf("MFA-gated admin must still be allowed (conditional), got denied: %+v", d)
	}
	if !d.Conditional {
		t.Errorf("access gated by aws:MultiFactorAuthPresent must be CONDITIONAL, got %+v", d)
	}
}

func TestGroupInheritedPolicy(t *testing.T) {
	user := "arn:aws:iam::111111111111:user/bob"
	group := "arn:aws:iam::111111111111:group/admins"
	s := NewStore([]model.Fact{
		{Kind: "membership", EdgeHint: "MemberOf", Source: user, Target: group},
		managed("arn:aws:iam::111111111111:policy/admin", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		attach(group, "arn:aws:iam::111111111111:policy/admin"),
	})
	if d := s.Evaluate(user, "secretsmanager:GetSecretValue", "arn:secret"); !d.Allowed {
		t.Errorf("user should inherit group's admin policy, got %+v", d)
	}
}
