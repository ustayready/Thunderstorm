package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Registry is the global real->fake bijection for one redaction run. It is
// deterministic within a run (same real -> same fake, so referential integrity holds)
// and irreversible across runs (salt is ephemeral and never persisted).
type Registry struct {
	salt  []byte
	m     map[string]string // real -> fake, memoized
	used  map[string]bool   // slug collision guard
	fakes map[string]bool   // every fake we produced (so the sweep never re-maps a fake)
	subs  []kv              // substitutable (real,fake) pairs for free-text scrubbing
	net   *netMapper
}

type kv struct{ real, fake string }

// NewRegistry creates a registry with a fresh ephemeral salt (irreversible).
func NewRegistry() (*Registry, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return newRegistryWithSalt(salt), nil
}

// newRegistryWithSalt is used by tests to pin the salt for reproducible fakes.
func newRegistryWithSalt(salt []byte) *Registry {
	return &Registry{salt: salt, m: map[string]string{}, used: map[string]bool{},
		fakes: map[string]bool{}, net: newNetMapper(salt)}
}

// markFake records a produced fake so the residual sweep never treats it as real.
func (r *Registry) markFake(f string) string { r.fakes[f] = true; return f }

// isFake reports whether s is a value this run produced (a scrub/sweep no-op guard).
func (r *Registry) isFake(s string) bool { return r.fakes[s] }

// slug returns a hex slug of nbytes derived from (salt, domain, real), unique within the
// run (extended on the rare collision).
func (r *Registry) slug(domain, real string, nbytes int) string {
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write([]byte(real))
	sum := mac.Sum(nil)
	for n := nbytes; n <= len(sum); n++ {
		s := hex.EncodeToString(sum[:n])
		if !r.used[domain+"|"+s] {
			r.used[domain+"|"+s] = true
			return s
		}
	}
	return hex.EncodeToString(sum)
}

// Get returns the fake for real, generating and memoizing it by type on first sight.
func (r *Registry) Get(real string, t idType) string {
	real = strings.TrimSpace(real)
	if real == "" {
		return real
	}
	if f, ok := r.m[real]; ok {
		return f
	}
	f := r.markFake(r.generate(real, t))
	r.m[real] = f
	// Register as a free-text substitution target (skip trivially short tokens that would
	// over-match inside unrelated words).
	if len(real) >= 4 {
		r.subs = append(r.subs, kv{real: real, fake: f})
	}
	return f
}

// Prepare orders substitution pairs longest-first so a compound id is replaced before any
// of its substrings. Call once after the registry is populated (before free-text scrub).
func (r *Registry) Prepare() {
	sortByRealLenDesc(r.subs)
}

// addSub registers an extra free-text substitution (e.g. an email local-part) so a bare
// mention of it in prose is replaced. Skips generic/stopword tokens (which are neither
// scrubbed nor treated as identifiers by the audit — keeping the two in agreement).
func (r *Registry) addSub(real, fake string) {
	if len(real) < 5 || stopwords[strings.ToLower(real)] {
		return
	}
	r.subs = append(r.subs, kv{real: real, fake: fake})
}

func (r *Registry) generate(real string, t idType) string {
	switch t {
	case tGCPProject:
		return "proj-" + r.slug("proj", real, 3)
	case tAWSAccount:
		return r.fakeAWSAccount(real)
	case tAzureSub, tGUID:
		return r.fakeGUID(real)
	case tSAEmail:
		return r.fakeSAEmail(real)
	case tUserEmail:
		return r.fakeUserEmail(real)
	case tDomain:
		return "dom-" + r.slug("dom", real, 3) + ".example"
	case tAWSARN:
		return r.fakeARN(real)
	case tHostname:
		return "host-" + r.slug("host", real, 3) + "." + r.domainFor(hostDomain(real))
	case tIP:
		if f := r.net.MapIP(real); f != "" {
			return f
		}
		return "ip-" + r.slug("ip", real, 3)
	case tCIDR:
		if f := r.net.MapCIDR(real); f != "" {
			return f
		}
		return "cidr-" + r.slug("cidr", real, 3)
	case tResourceName:
		return "res-" + r.slug("res", real, 3)
	case tOpaqueName:
		return "val-" + r.slug("val", real, 3)
	default:
		return "id-" + r.slug("id", real, 3)
	}
}

// Token returns an opaque prefixed token for an internal FK identifier (edge_id, path_id,
// site_id, value_ref) — consistent per real so foreign keys line up.
func (r *Registry) Token(prefix, real string) string {
	real = strings.TrimSpace(real)
	if real == "" {
		return real
	}
	key := "tok:" + prefix + ":" + real
	if f, ok := r.m[key]; ok {
		return f
	}
	f := r.markFake(prefix + "-" + r.slug(prefix, real, 4))
	r.m[key] = f
	return f
}

func (r *Registry) fakeAWSAccount(real string) string {
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte("awsacct\x00" + real))
	n := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	return r.markFake(fmt.Sprintf("%012d", 100000000000+(n%900000000000))) // 12 digits, no leading zero
}

func (r *Registry) fakeGUID(real string) string {
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte("guid\x00" + real))
	b := mac.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4 shape
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// projectOfSA extracts the real project/home of a service-account email.
func projectOfSA(email string) (local, domain string) {
	i := strings.IndexByte(email, '@')
	if i < 0 {
		return email, ""
	}
	return email[:i], email[i+1:]
}

func (r *Registry) fakeSAEmail(real string) string {
	realLocal, domain := projectOfSA(real)
	local := "sa-" + r.slug("sa", real, 3)
	r.addSub(realLocal, local) // replace a bare "deployer"/"terraform"-style mention in prose
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		proj := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
		return local + "@" + r.Get(proj, tGCPProject) + ".iam.gserviceaccount.com"
	}
	// @appspot / @developer / @cloudservices etc. — keep the suffix (structural), fake local.
	return local + "@" + domain
}

func (r *Registry) fakeUserEmail(real string) string {
	i := strings.IndexByte(real, '@')
	if i < 0 {
		return "user-" + r.slug("user", real, 3)
	}
	local := "user-" + r.slug("user", real, 3)
	r.addSub(real[:i], local)
	return local + "@" + r.domainFor(real[i+1:])
}

func (r *Registry) fakeARN(real string) string {
	// arn:partition:service:region:account:resource...
	parts := strings.SplitN(real, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return "arn:aws:x:::" + r.slug("arn", real, 4)
	}
	if isPredefinedRole(real) {
		return real
	}
	account := parts[4]
	if account != "" && account != "aws" {
		account = r.fakeAWSAccount(account)
	}
	// resource: keep the type prefix (role/, instance/, function:...), fake the name.
	res := parts[5]
	res = r.fakeResourcePath(res)
	return strings.Join([]string{"arn", parts[1], parts[2], parts[3], account, res}, ":")
}

// fakeResourcePath keeps a leading type token (before the first '/' or ':') and fakes the
// remaining name, so "role/AdminRole" -> "role/res-xxxx", "function:foo" -> "function:res-xxxx".
func (r *Registry) fakeResourcePath(res string) string {
	sep := strings.IndexAny(res, "/:")
	if sep < 0 {
		return "res-" + r.slug("res", res, 3)
	}
	return res[:sep+1] + "res-" + r.slug("res", res, 3)
}

func (r *Registry) domainFor(real string) string {
	if real == "" {
		return "dom-" + r.slug("dom", "empty", 3) + ".example"
	}
	return r.Get(real, tDomain)
}

func hostDomain(host string) string {
	i := strings.IndexByte(host, '.')
	if i < 0 {
		return host
	}
	return host[i+1:]
}
