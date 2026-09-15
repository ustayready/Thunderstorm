package exposure

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
)

// A secret-exposure SITE is, by catalog definition, a location that holds a
// credential. So a non-empty value returned at the site's response path is a
// hit. Entropy/pattern signals refine confidence but do not gate the hit — we
// prefer catching a real secret over silence.

// maxValueBytes caps a captured value so a giant blob (userdata scripts, large
// config bodies) is preserved but does not bloat the bundle unboundedly.
const maxValueBytes = 256 * 1024

// CapValue returns the raw captured value, truncated (with a marker) if it exceeds
// the cap. This is the actual loot — the operator needs the real value to use it.
func CapValue(value string) string {
	if len(value) > maxValueBytes {
		return value[:maxValueBytes] + "…[truncated " + itoa(len(value)-maxValueBytes) + " more bytes]"
	}
	return value
}

// Redact turns a raw secret into a salted-hash fingerprint (for dedup / integrity).
func Redact(value, salt string) string {
	sum := sha256.Sum256([]byte(salt + value))
	h := hex.EncodeToString(sum[:])[:16]
	preview := ""
	if n := len(value); n > 0 {
		last := value
		if n > 4 {
			last = value[n-4:]
		}
		preview = "…" + last
	}
	return "sha256:" + h + " len=" + itoa(len(value)) + " " + preview
}

// hardSecretKinds are location kinds where a non-empty value is inherently a
// credential (flag any value). Every other kind is "soft" — a value there is
// only flagged if it LOOKS like a secret (pattern or high entropy), so benign
// descriptions/tags/config fields don't produce false positives.
var hardSecretKinds = map[string]bool{
	"secret_value":         true,
	"connection_string":    true,
	"certificate_material": true,
}

// Assess decides whether a value at a given location kind is a credential hit,
// with a coarse confidence. Hard locations flag any value; soft locations
// require a credential pattern or high entropy.
func Assess(value, locationKind string) (hit bool, confidence float64) {
	v := strings.TrimSpace(value)
	if v == "" {
		return false, 0
	}
	if hasCredentialPattern(v) {
		return true, 0.99
	}
	if hardSecretKinds[locationKind] {
		return true, 0.75 // inherently-sensitive location, value present
	}
	if looksLikeToken(v) {
		return true, 0.8 // a single high-entropy token at a soft location
	}
	return false, 0.2 // soft location, plain value (prose/tag/description) — not a credential
}

// looksLikeToken is true for a single opaque high-entropy string — the shape of
// a real secret. It excludes natural-language prose (which contains whitespace
// and sits near ~4 bits/char), so descriptions/tags aren't false-flagged.
func looksLikeToken(v string) bool {
	if len(v) < 20 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	return shannon(v) > 3.5
}

func hasCredentialPattern(v string) bool {
	patterns := []string{
		"AKIA", "ASIA", // AWS access key ids
		"-----BEGIN", "PRIVATE KEY",
		"aws_secret_access_key", "password", "passwd",
		"xoxb-", "xoxp-", // slack
		"ghp_", "github_pat_",
		"eyJ", // JWT-ish
	}
	low := strings.ToLower(v)
	for _, p := range patterns {
		if strings.Contains(v, p) || strings.Contains(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// shannon computes Shannon entropy (bits/char) — high for random secrets.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
