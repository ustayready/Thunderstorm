package policy

import "testing"

func TestMatchAction(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"s3:GetObject", "s3:GetObject", true},
		{"S3:getobject", "s3:GetObject", true}, // case-insensitive
		{"s3:*Object", "s3:GetObject", true},
		{"iam:PassRole", "iam:passrole", true},
		{"ec2:Describe*", "ec2:DescribeInstances", true},
		{"s3:GetObject", "s3:GetObjectVersion", false},
		{"lambda:InvokeFunction", "s3:GetObject", false},
	}
	for _, c := range cases {
		if got := MatchAction(c.pattern, c.action); got != c.want {
			t.Errorf("MatchAction(%q,%q)=%v want %v", c.pattern, c.action, got, c.want)
		}
	}
}

func TestMatchResource(t *testing.T) {
	cases := []struct {
		pattern, arn string
		want         bool
	}{
		{"*", "arn:aws:s3:::bucket/key", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other/key", false},
		{"arn:aws:s3:::bucket", "arn:aws:s3:::bucket", true},
		{"arn:aws:iam::123456789012:role/*", "arn:aws:iam::123456789012:role/admin", true},
		{"arn:aws:iam::123456789012:role/team-?", "arn:aws:iam::123456789012:role/team-a", true},
		{"arn:aws:iam::123456789012:role/team-?", "arn:aws:iam::123456789012:role/team-ab", false},
		{"arn:aws:s3:::Bucket/*", "arn:aws:s3:::bucket/key", false}, // case-sensitive
	}
	for _, c := range cases {
		if got := MatchResource(c.pattern, c.arn); got != c.want {
			t.Errorf("MatchResource(%q,%q)=%v want %v", c.pattern, c.arn, got, c.want)
		}
	}
}

func TestExpandVariables(t *testing.T) {
	vars := map[string]string{"aws:username": "alice"}
	if got := ExpandVariables("arn:aws:s3:::bucket/${aws:username}/*", vars); got != "arn:aws:s3:::bucket/alice/*" {
		t.Errorf("expand username = %q", got)
	}
	if got := ExpandVariables("${*}", vars); got != "*" {
		t.Errorf("expand literal star = %q", got)
	}
	// unknown var becomes an unmatchable sentinel (never a false allow)
	got := ExpandVariables("bucket/${aws:PrincipalTag/team}", vars)
	if MatchResource(got, "bucket/anything") {
		t.Errorf("unresolved variable must not match: %q", got)
	}
}

func ctx(kv map[string][]string) EvalContext { return EvalContext{Known: kv} }

func TestConditionStringAndDefaults(t *testing.T) {
	cond := Condition{"StringEquals": {"aws:PrincipalOrgID": {"o-abc123"}}}
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:PrincipalOrgID": {"o-abc123"}})); got != TriTrue {
		t.Errorf("matching org id => %v want true", got)
	}
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:PrincipalOrgID": {"o-zzz999"}})); got != TriFalse {
		t.Errorf("wrong org id => %v want false", got)
	}
	// statically-knowable key that is absent => false (not unresolved)
	if got := EvalCondition(cond, ctx(map[string][]string{})); got != TriFalse {
		t.Errorf("absent static key => %v want false", got)
	}
}

func TestConditionRequestTimeUnresolved(t *testing.T) {
	// aws:SourceIp is request-time-only; with no known value it must be UNRESOLVED,
	// never silently true or false.
	cond := Condition{"IpAddress": {"aws:SourceIp": {"10.0.0.0/8"}}}
	if got := EvalCondition(cond, ctx(nil)); got != TriUnresolved {
		t.Errorf("unknown SourceIp => %v want unresolved", got)
	}
	// MFA present, unknown => unresolved
	mfa := Condition{"Bool": {"aws:MultiFactorAuthPresent": {"true"}}}
	if got := EvalCondition(mfa, ctx(nil)); got != TriUnresolved {
		t.Errorf("unknown MFA => %v want unresolved", got)
	}
}

func TestConditionIpAddressResolved(t *testing.T) {
	cond := Condition{"IpAddress": {"aws:SourceIp": {"10.0.0.0/8"}}}
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:SourceIp": {"10.1.2.3"}})); got != TriTrue {
		t.Errorf("in-range ip => %v want true", got)
	}
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:SourceIp": {"192.168.1.1"}})); got != TriFalse {
		t.Errorf("out-of-range ip => %v want false", got)
	}
}

func TestConditionIfExists(t *testing.T) {
	cond := Condition{"StringEqualsIfExists": {"aws:PrincipalTag/team": {"blue"}}}
	// key absent + IfExists => passes
	if got := EvalCondition(cond, ctx(nil)); got != TriTrue {
		t.Errorf("IfExists absent => %v want true", got)
	}
	// key present + mismatch => false
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:PrincipalTag/team": {"red"}})); got != TriFalse {
		t.Errorf("IfExists present mismatch => %v want false", got)
	}
}

func TestConditionNull(t *testing.T) {
	// Null:true matches when key absent
	nullTrue := Condition{"Null": {"aws:PrincipalTag/team": {"true"}}}
	if got := EvalCondition(nullTrue, ctx(nil)); got != TriTrue {
		t.Errorf("Null:true absent => %v want true", got)
	}
	if got := EvalCondition(nullTrue, ctx(map[string][]string{"aws:PrincipalTag/team": {"blue"}})); got != TriFalse {
		t.Errorf("Null:true present => %v want false", got)
	}
	// Null:false matches when key present
	nullFalse := Condition{"Null": {"aws:PrincipalTag/team": {"false"}}}
	if got := EvalCondition(nullFalse, ctx(map[string][]string{"aws:PrincipalTag/team": {"blue"}})); got != TriTrue {
		t.Errorf("Null:false present => %v want true", got)
	}
}

func TestConditionForAllForAny(t *testing.T) {
	all := Condition{"ForAllValues:StringEquals": {"aws:TagKeys": {"team", "env"}}}
	if got := EvalCondition(all, ctx(map[string][]string{"aws:TagKeys": {"team", "env"}})); got != TriTrue {
		t.Errorf("ForAllValues subset => %v want true", got)
	}
	if got := EvalCondition(all, ctx(map[string][]string{"aws:TagKeys": {"team", "secret"}})); got != TriFalse {
		t.Errorf("ForAllValues with extra => %v want false", got)
	}
	any := Condition{"ForAnyValue:StringEquals": {"aws:TagKeys": {"team"}}}
	if got := EvalCondition(any, ctx(map[string][]string{"aws:TagKeys": {"env", "team"}})); got != TriTrue {
		t.Errorf("ForAnyValue hit => %v want true", got)
	}
	if got := EvalCondition(any, ctx(map[string][]string{"aws:TagKeys": {"env"}})); got != TriFalse {
		t.Errorf("ForAnyValue miss => %v want false", got)
	}
}

func TestConditionMultipleClausesAND(t *testing.T) {
	// two operators must both hold; one false => whole block false
	cond := Condition{
		"StringEquals": {"aws:PrincipalOrgID": {"o-abc123"}},
		"IpAddress":    {"aws:SourceIp": {"10.0.0.0/8"}},
	}
	// org ok, ip unknown => unresolved (not false)
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:PrincipalOrgID": {"o-abc123"}})); got != TriUnresolved {
		t.Errorf("org-ok ip-unknown => %v want unresolved", got)
	}
	// org wrong, ip unknown => FALSE wins over unresolved
	if got := EvalCondition(cond, ctx(map[string][]string{"aws:PrincipalOrgID": {"o-wrong"}})); got != TriFalse {
		t.Errorf("org-wrong => %v want false (false beats unresolved)", got)
	}
}

func TestParsePolicyPrincipalForms(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"},
	  {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111:root","arn:aws:iam::222:user/bob"]},"Action":["s3:PutObject"],"Resource":"arn:aws:s3:::b/*"},
	  {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}
	]}`
	pd, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pd.Statements) != 3 {
		t.Fatalf("statements = %d want 3", len(pd.Statements))
	}
	if !pd.Statements[0].Principal.IsPublic() {
		t.Errorf("stmt0 should be public")
	}
	if got := pd.Statements[1].Principal.AWSPrincipals(); len(got) != 2 {
		t.Errorf("stmt1 AWS principals = %v want 2", got)
	}
	if got := pd.Statements[1].Action; len(got) != 1 || got[0] != "s3:PutObject" {
		t.Errorf("stmt1 action = %v", got)
	}
	if got := pd.Statements[2].Principal.ByType["Service"]; len(got) != 1 || got[0] != "lambda.amazonaws.com" {
		t.Errorf("stmt2 service principal = %v", got)
	}
}

func TestAccountOf(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::123456789012:role/admin": "123456789012",
		"arn:aws:s3:::bucket":                  "", // s3 arns have no account field
		"123456789012":                         "123456789012",
		"*":                                    "",
	}
	for in, want := range cases {
		if got := AccountOf(in); got != want {
			t.Errorf("AccountOf(%q)=%q want %q", in, got, want)
		}
	}
}
