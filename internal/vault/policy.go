package vault

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Capabilities
const (
	CapCreate = "create"
	CapRead   = "read"
	CapUpdate = "update"
	CapPatch  = "patch"
	CapDelete = "delete"
	CapList   = "list"
	CapSudo   = "sudo"
	CapDeny   = "deny"
	CapRoot   = "root"
)

var validCaps = map[string]bool{CapCreate: true, CapRead: true, CapUpdate: true, CapPatch: true, CapDelete: true, CapList: true, CapSudo: true, CapDeny: true}

// PathRule is one `path "..." { capabilities = [...] }` block.
type PathRule struct {
	Pattern      string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

// Policy is a named set of rules.
type Policy struct {
	Name  string     `json:"name"`
	Raw   string     `json:"policy"`
	Rules []PathRule `json:"rules"`
}

// ParsePolicy accepts the HCL subset used by OpenBao/Vault, or JSON.
func ParsePolicy(name, raw string) (*Policy, error) {
	p := &Policy{Name: name, Raw: raw}
	trim := strings.TrimSpace(raw)
	if strings.HasPrefix(trim, "{") {
		var j struct {
			Path map[string]struct {
				Capabilities []string `json:"capabilities"`
			} `json:"path"`
		}
		if err := json.Unmarshal([]byte(trim), &j); err != nil {
			return nil, fmt.Errorf("invalid JSON policy: %v", err)
		}
		for pat, r := range j.Path {
			p.Rules = append(p.Rules, PathRule{Pattern: pat, Capabilities: r.Capabilities})
		}
	} else {
		rules, err := parseHCLPolicy(raw)
		if err != nil {
			return nil, err
		}
		p.Rules = rules
	}
	for i, r := range p.Rules {
		if r.Pattern == "" {
			return nil, fmt.Errorf("rule %d: empty path", i+1)
		}
		if strings.Contains(strings.TrimSuffix(r.Pattern, "*"), "*") {
			return nil, fmt.Errorf("path %q: '*' is only allowed at the end", r.Pattern)
		}
		if len(r.Capabilities) == 0 {
			return nil, fmt.Errorf("path %q: no capabilities", r.Pattern)
		}
		for _, c := range r.Capabilities {
			if !validCaps[c] {
				return nil, fmt.Errorf("path %q: invalid capability %q", r.Pattern, c)
			}
		}
		p.Rules[i].Pattern = strings.TrimPrefix(r.Pattern, "/")
	}
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].Pattern < p.Rules[j].Pattern })
	return p, nil
}

type tok struct {
	kind byte // 's' string, 'i' ident, or punctuation char
	val  string
	line int
}

func lexHCL(src string) ([]tok, error) {
	var out []tok
	line := 1
	r := []rune(src)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\n':
			line++
		case unicode.IsSpace(c):
		case c == '#' || (c == '/' && i+1 < len(r) && r[i+1] == '/'):
			for i < len(r) && r[i] != '\n' {
				i++
			}
			line++
		case c == '/' && i+1 < len(r) && r[i+1] == '*':
			i += 2
			for i+1 < len(r) && !(r[i] == '*' && r[i+1] == '/') {
				if r[i] == '\n' {
					line++
				}
				i++
			}
			i++
		case c == '"':
			var sb strings.Builder
			i++
			for ; i < len(r) && r[i] != '"'; i++ {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				if r[i] == '\n' {
					return nil, fmt.Errorf("line %d: unterminated string", line)
				}
				sb.WriteRune(r[i])
			}
			if i >= len(r) {
				return nil, fmt.Errorf("line %d: unterminated string", line)
			}
			out = append(out, tok{'s', sb.String(), line})
		case strings.ContainsRune("{}[]=,", c):
			out = append(out, tok{byte(c), string(c), line})
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '_' || r[j] == '-') {
				j++
			}
			out = append(out, tok{'i', string(r[i:j]), line})
			i = j - 1
		default:
			return nil, fmt.Errorf("line %d: unexpected character %q", line, c)
		}
	}
	return out, nil
}

func parseHCLPolicy(src string) ([]PathRule, error) {
	toks, err := lexHCL(src)
	if err != nil {
		return nil, err
	}
	var rules []PathRule
	i := 0
	expect := func(k byte) (tok, error) {
		if i >= len(toks) {
			return tok{}, fmt.Errorf("unexpected end of policy")
		}
		t := toks[i]
		if t.kind != k {
			return t, fmt.Errorf("line %d: expected %q, got %q", t.line, string(k), t.val)
		}
		i++
		return t, nil
	}
	for i < len(toks) {
		t := toks[i]
		if t.kind != 'i' || t.val != "path" {
			return nil, fmt.Errorf("line %d: expected 'path', got %q", t.line, t.val)
		}
		i++
		pt, err := expect('s')
		if err != nil {
			return nil, err
		}
		if _, err := expect('{'); err != nil {
			return nil, err
		}
		rule := PathRule{Pattern: pt.val}
		for i < len(toks) && toks[i].kind != '}' {
			key, err := expect('i')
			if err != nil {
				return nil, err
			}
			if _, err := expect('='); err != nil {
				return nil, err
			}
			switch key.val {
			case "capabilities":
				if _, err := expect('['); err != nil {
					return nil, err
				}
				for i < len(toks) && toks[i].kind != ']' {
					s, err := expect('s')
					if err != nil {
						return nil, err
					}
					rule.Capabilities = append(rule.Capabilities, s.val)
					if i < len(toks) && toks[i].kind == ',' {
						i++
					}
				}
				if _, err := expect(']'); err != nil {
					return nil, err
				}
			case "policy": // legacy shorthand
				s, err := expect('s')
				if err != nil {
					return nil, err
				}
				switch s.val {
				case "read":
					rule.Capabilities = append(rule.Capabilities, CapRead, CapList)
				case "write":
					rule.Capabilities = append(rule.Capabilities, CapCreate, CapRead, CapUpdate, CapDelete, CapList)
				case "deny":
					rule.Capabilities = append(rule.Capabilities, CapDeny)
				case "sudo":
					rule.Capabilities = append(rule.Capabilities, CapCreate, CapRead, CapUpdate, CapDelete, CapList, CapSudo)
				default:
					return nil, fmt.Errorf("line %d: invalid policy shorthand %q", s.line, s.val)
				}
			default:
				return nil, fmt.Errorf("line %d: unsupported key %q", key.line, key.val)
			}
		}
		if _, err := expect('}'); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ---------------- ACL evaluation ----------------

type aclRule struct {
	pattern string
	caps    map[string]bool
}

// ACL is the merged result of a token's policies.
type ACL struct {
	root  bool
	rules map[string]*aclRule
}

// NewACL merges policies. The "root" policy grants everything.
func NewACL(policies []*Policy) *ACL {
	a := &ACL{rules: map[string]*aclRule{}}
	for _, p := range policies {
		if p == nil {
			continue
		}
		if p.Name == "root" {
			a.root = true
			continue
		}
		for _, r := range p.Rules {
			ar, ok := a.rules[r.Pattern]
			if !ok {
				ar = &aclRule{pattern: r.Pattern, caps: map[string]bool{}}
				a.rules[r.Pattern] = ar
			}
			for _, c := range r.Capabilities {
				ar.caps[c] = true
			}
		}
	}
	return a
}

// matchPattern supports '+' (one segment) and trailing '*' (prefix glob).
func matchPattern(pattern, path string) bool {
	glob := strings.HasSuffix(pattern, "*")
	if glob {
		pattern = strings.TrimSuffix(pattern, "*")
	}
	if !strings.Contains(pattern, "+") {
		if glob {
			return strings.HasPrefix(path, pattern)
		}
		return pattern == path
	}
	ps := strings.Split(pattern, "/")
	xs := strings.Split(path, "/")
	for i, seg := range ps {
		last := i == len(ps)-1
		if i >= len(xs) {
			return false
		}
		if last && glob {
			if seg == "+" {
				return true
			}
			return strings.HasPrefix(strings.Join(xs[i:], "/"), seg)
		}
		if seg != "+" && seg != xs[i] {
			return false
		}
	}
	if glob {
		return true
	}
	return len(xs) == len(ps)
}

// moreSpecific reports whether pattern a beats b (Vault priority rules).
func moreSpecific(a, b string) bool {
	firstWild := func(s string) int {
		i := strings.IndexAny(s, "+*")
		if i < 0 {
			return len(s) + 1
		}
		return i
	}
	if fa, fb := firstWild(a), firstWild(b); fa != fb {
		return fa > fb
	}
	ga, gb := strings.HasSuffix(a, "*"), strings.HasSuffix(b, "*")
	if ga != gb {
		return !ga
	}
	pa, pb := strings.Count(a, "+"), strings.Count(b, "+")
	if pa != pb {
		return pa < pb
	}
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a < b
}

func (a *ACL) bestRule(path string) *aclRule {
	var best *aclRule
	for _, r := range a.rules {
		if matchPattern(r.pattern, path) && (best == nil || moreSpecific(r.pattern, best.pattern)) {
			best = r
		}
	}
	return best
}

// Capabilities returns the capabilities granted on path.
func (a *ACL) Capabilities(path string) []string {
	if a.root {
		return []string{CapRoot}
	}
	r := a.bestRule(path)
	if r == nil || r.caps[CapDeny] {
		return []string{CapDeny}
	}
	var out []string
	for c := range r.caps {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Allowed reports whether any of caps is granted (and sudo, if required).
func (a *ACL) Allowed(path string, needSudo bool, caps ...string) bool {
	if a.root {
		return true
	}
	r := a.bestRule(path)
	if r == nil || r.caps[CapDeny] {
		return false
	}
	if needSudo && !r.caps[CapSudo] {
		return false
	}
	for _, c := range caps {
		if r.caps[c] {
			return true
		}
	}
	return false
}

// AnyUnder reports whether the ACL grants anything at or below prefix
// (used by the UI to decide which mounts to show).
func (a *ACL) AnyUnder(prefix string) bool {
	if a.root {
		return true
	}
	for _, r := range a.rules {
		if r.caps[CapDeny] && len(r.caps) == 1 {
			continue
		}
		pat := strings.TrimSuffix(r.pattern, "*")
		if strings.HasPrefix(pat, prefix) || matchPattern(r.pattern, prefix) || strings.HasPrefix(prefix, pat) && strings.HasSuffix(r.pattern, "*") {
			return true
		}
		if strings.Contains(pat, "+") {
			// approximate: compare first segment
			ps := strings.SplitN(pat, "/", 2)
			xs := strings.SplitN(prefix, "/", 2)
			if ps[0] == "+" || ps[0] == xs[0] {
				return true
			}
		}
	}
	return false
}

func (a *ACL) IsRoot() bool { return a.root }

const DefaultPolicy = `# Allow tokens to look up their own properties
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow tokens to renew and revoke themselves
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# Allow a token to look up its own capabilities on a path
path "sys/capabilities-self" {
  capabilities = ["update"]
}

# Allow the UI to discover mounts the token can use
path "sys/internal/ui/*" {
  capabilities = ["read"]
}

# Private per-token storage
path "cubbyhole/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Response wrapping
path "sys/wrapping/wrap" {
  capabilities = ["update"]
}
path "sys/wrapping/lookup" {
  capabilities = ["update"]
}
path "sys/wrapping/unwrap" {
  capabilities = ["update"]
}
`
