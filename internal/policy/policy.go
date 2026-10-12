// Package policy implements POL-002 and DST-001: one validated, immutable
// snapshot of literal capabilities. No parsing operation performs network IO.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const MaxPolicyBytes = 64 << 10

type ModelRoute struct {
	ID              string   `json:"id"`
	LocalPath       string   `json:"local_path"`
	UpstreamURL     string   `json:"upstream_url"`
	Protocol        string   `json:"protocol"`
	AllowedModels   []string `json:"allowed_models"`
	CredentialRef   string   `json:"credential_ref"`
	MaxOutputTokens int64    `json:"max_output_tokens"`
}

type FetchResource struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type Policy struct {
	limits Limits
	digest string
	model  *ModelRoute
	fetch  map[string]FetchResource
	denied []netip.Prefix
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func Parse(data []byte) (*Policy, error) {
	if len(data) == 0 || len(data) > MaxPolicyBytes {
		return nil, errors.New("policy size invalid")
	}
	var wire struct {
		SchemaVersion  int             `json:"schema_version"`
		Limits         *Limits         `json:"limits"`
		ModelRoutes    []ModelRoute    `json:"model_routes"`
		FetchResources []FetchResource `json:"fetch_resources"`
		DeniedCIDRs    []string        `json:"denied_cidrs"`
	}
	if err := DecodeStrict(data, 32, &wire); err != nil {
		return nil, err
	}
	if wire.SchemaVersion != 1 || wire.Limits == nil || wire.ModelRoutes == nil || wire.FetchResources == nil || wire.DeniedCIDRs == nil {
		return nil, errors.New("missing or unsupported policy fields")
	}
	if err := wire.Limits.Validate(); err != nil {
		return nil, err
	}
	if len(wire.ModelRoutes) > 1 || len(wire.FetchResources) > 64 || len(wire.DeniedCIDRs) > 256 {
		return nil, errors.New("too many capabilities")
	}
	p := &Policy{limits: *wire.Limits, fetch: make(map[string]FetchResource)}
	ids := make(map[string]bool)
	for _, r := range wire.ModelRoutes {
		if !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.CredentialRef) || r.LocalPath != "/v1/chat/completions" || r.Protocol != "openai-chat-v1" || r.MaxOutputTokens < 1 || r.MaxOutputTokens > 8192 || len(r.AllowedModels) == 0 || len(r.AllowedModels) > 64 {
			return nil, errors.New("invalid model capability")
		}
		if err := ValidateURL(r.UpstreamURL); err != nil {
			return nil, err
		}
		seen := make(map[string]bool)
		for _, m := range r.AllowedModels {
			if len(m) == 0 || len(m) > 128 || strings.TrimSpace(m) != m || strings.ContainsAny(m, "\x00\r\n") || seen[m] {
				return nil, errors.New("invalid allowed model")
			}
			seen[m] = true
		}
		ids[r.ID] = true
		r.AllowedModels = append([]string(nil), r.AllowedModels...)
		p.model = &r
	}
	for _, r := range wire.FetchResources {
		if !idPattern.MatchString(r.ID) || ids[r.ID] {
			return nil, errors.New("invalid or duplicate capability ID")
		}
		if err := ValidateURL(r.URL); err != nil {
			return nil, err
		}
		ids[r.ID] = true
		p.fetch[r.ID] = r
	}
	seenCIDRs := make(map[netip.Prefix]bool)
	for _, s := range wire.DeniedCIDRs {
		prefix, err := netip.ParsePrefix(s)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || seenCIDRs[prefix] {
			return nil, errors.New("invalid denied CIDR")
		}
		seenCIDRs[prefix] = true
		p.denied = append(p.denied, prefix)
	}
	hash := sha256.Sum256(data)
	p.digest = hex.EncodeToString(hash[:])
	return p, nil
}

func (p *Policy) Limits() Limits { return p.limits }
func (p *Policy) Digest() string { return p.digest }
func (p *Policy) Model() (ModelRoute, bool) {
	if p.model == nil {
		return ModelRoute{}, false
	}
	r := *p.model
	r.AllowedModels = append([]string(nil), r.AllowedModels...)
	return r, true
}
func (p *Policy) Fetch(id string) (FetchResource, bool) { r, ok := p.fetch[id]; return r, ok }
func (p *Policy) DeniedCIDRs() []netip.Prefix           { return append([]netip.Prefix(nil), p.denied...) }

// ValidateURL deliberately accepts only the v1 canonical destination grammar.
func ValidateURL(s string) error {
	bad := errors.New("noncanonical destination URL")
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, "\\?#%") {
		return bad
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Host != u.Hostname() || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return bad
	}
	host := u.Hostname()
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return bad
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return bad
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return bad
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return bad
			}
		}
	}
	path := u.Path
	if path == "" {
		return bad
	} // Explicit / is the canonical representation.
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return bad
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return bad
		}
	}
	for _, c := range []byte(path) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~/", rune(c))) {
			return bad
		}
	}
	if u.String() != s {
		return bad
	}
	return nil
}
