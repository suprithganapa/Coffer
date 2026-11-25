package vault

import (
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	tokenPrefix     = "cof."
	DefaultTokenTTL = 768 * time.Hour
	MaxTokenTTL     = 768 * time.Hour
	wrappingPolicy  = "response-wrapping"
)

// TokenEntry is the stored form of a token (keyed by its SHA-256).
type TokenEntry struct {
	IDHash         string            `json:"id_hash"`
	Accessor       string            `json:"accessor"`
	Parent         string            `json:"parent,omitempty"` // parent id hash
	Policies       []string          `json:"policies"`
	Path           string            `json:"path"`
	Meta           map[string]string `json:"meta,omitempty"`
	DisplayName    string            `json:"display_name"`
	NumUses        int               `json:"num_uses"`
	CreationTime   time.Time         `json:"creation_time"`
	TTL            time.Duration     `json:"ttl"`
	ExplicitMaxTTL time.Duration     `json:"explicit_max_ttl"`
	ExpireTime     time.Time         `json:"expire_time"`
	Renewable      bool              `json:"renewable"`
	Orphan         bool              `json:"orphan"`
	Type           string            `json:"type"`
}

func (t *TokenEntry) expired() bool {
	return !t.ExpireTime.IsZero() && time.Now().After(t.ExpireTime)
}

func (t *TokenEntry) IsRoot() bool {
	for _, p := range t.Policies {
		if p == "root" {
			return true
		}
	}
	return false
}

func (c *Core) tokenView() *View { return c.barrier.View("sys/token/") }

func expireKey(t time.Time, hash string) string {
	return fmt.Sprintf("expire/%020d/%s", t.Unix(), hash)
}

// createToken persists a new token derived from parent (nil = no parent).
func (c *Core) createToken(te *TokenEntry, parent *TokenEntry) (*TokenEntry, string, error) {
	return c.createTokenWithID(te, parent, tokenPrefix+randomString(24))
}

// CreateRootToken mints a root token, optionally with a fixed id (dev mode).
func (c *Core) CreateRootToken(id string) (string, error) {
	if c.Sealed() {
		return "", ErrSealed
	}
	if id == "" {
		id = tokenPrefix + randomString(24)
	}
	if existing, _ := c.LookupToken(id); existing != nil {
		return id, nil
	}
	_, tok, err := c.createTokenWithID(&TokenEntry{Policies: []string{"root"}, DisplayName: "root", Path: "sys/dev"}, nil, id)
	return tok, err
}

func (c *Core) createTokenWithID(te *TokenEntry, parent *TokenEntry, token string) (*TokenEntry, string, error) {
	te.IDHash = sha256hex(token)
	te.Accessor = randomString(24)
	te.CreationTime = now()
	te.Type = "service"
	te.Policies = uniqSorted(te.Policies)
	if parent != nil && !te.Orphan {
		te.Parent = parent.IDHash
	} else {
		te.Orphan = true
	}
	isRoot := te.IsRoot()
	if !isRoot {
		if te.TTL <= 0 {
			te.TTL = DefaultTokenTTL
		}
		maxTTL := MaxTokenTTL
		if te.ExplicitMaxTTL > 0 && te.ExplicitMaxTTL < maxTTL {
			maxTTL = te.ExplicitMaxTTL
		}
		if te.TTL > maxTTL {
			te.TTL = maxTTL
		}
		te.ExpireTime = te.CreationTime.Add(te.TTL)
		// a child can never outlive its parent
		if parent != nil && !te.Orphan && !parent.ExpireTime.IsZero() && te.ExpireTime.After(parent.ExpireTime) {
			te.ExpireTime = parent.ExpireTime
			te.TTL = time.Until(parent.ExpireTime).Round(time.Second)
		}
	} else if te.TTL > 0 {
		te.ExpireTime = te.CreationTime.Add(te.TTL)
	}
	v := c.tokenView()
	if err := v.PutJSON("id/"+te.IDHash, te); err != nil {
		return nil, "", err
	}
	if err := v.Put("accessor/"+te.Accessor, []byte(te.IDHash)); err != nil {
		return nil, "", err
	}
	if te.Parent != "" {
		v.Put("parent/"+te.Parent+"/"+te.IDHash, []byte{1})
	}
	if !te.ExpireTime.IsZero() {
		v.Put(expireKey(te.ExpireTime, te.IDHash), []byte{1})
	}
	return te, token, nil
}

// LookupToken resolves a raw token. Returns nil,nil if invalid/expired.
func (c *Core) LookupToken(token string) (*TokenEntry, error) {
	if token == "" {
		return nil, nil
	}
	return c.lookupHash(sha256hex(token))
}

func (c *Core) lookupHash(hash string) (*TokenEntry, error) {
	var te TokenEntry
	ok, err := c.tokenView().GetJSON("id/"+hash, &te)
	if err != nil || !ok {
		return nil, err
	}
	if te.expired() {
		go c.revokeTree(hash)
		return nil, nil
	}
	if te.NumUses < 0 { // use count exhausted
		return nil, nil
	}
	return &te, nil
}

func (c *Core) lookupAccessor(acc string) (*TokenEntry, error) {
	h, err := c.tokenView().Get("accessor/" + acc)
	if err != nil || h == nil {
		return nil, err
	}
	return c.lookupHash(string(h))
}

// useToken decrements a limited-use token. It reports whether this was the
// final use, in which case the caller revokes the token after the request.
func (c *Core) useToken(te *TokenEntry) (bool, error) {
	te.NumUses--
	last := te.NumUses <= 0
	stored := *te
	if last {
		stored.NumUses = -1 // exhausted: further lookups fail immediately
	}
	return last, c.tokenView().PutJSON("id/"+te.IDHash, &stored)
}

// revokeTree revokes a token and all of its descendants.
func (c *Core) revokeTree(hash string) {
	c.revokeMu.Lock()
	defer c.revokeMu.Unlock()
	c.revokeTreeLocked(hash, 0)
}

func (c *Core) revokeTreeLocked(hash string, depth int) {
	if depth > 64 {
		return
	}
	v := c.tokenView()
	children, _ := v.List("parent/" + hash + "/")
	for _, ch := range children {
		c.revokeTreeLocked(strings.TrimSuffix(ch, "/"), depth+1)
	}
	v.DeletePrefix("parent/" + hash + "/")
	c.revokeOne(hash)
}

func (c *Core) revokeOne(hash string) {
	v := c.tokenView()
	var te TokenEntry
	ok, _ := v.GetJSON("id/"+hash, &te)
	if !ok {
		return
	}
	v.Delete("accessor/" + te.Accessor)
	if !te.ExpireTime.IsZero() {
		v.Delete(expireKey(te.ExpireTime, hash))
	}
	if te.Parent != "" {
		v.Delete("parent/" + te.Parent + "/" + hash)
	}
	v.Delete("id/" + hash)
	// destroy the token's cubbyhole
	if m, _, _ := c.route("cubbyhole/"); m != nil {
		c.barrier.DeletePrefix("logical/" + m.UUID + "/" + hash + "/")
	}
}

// RevokeOrphan revokes only this token; children become orphans.
func (c *Core) revokeOrphan(hash string) {
	c.revokeMu.Lock()
	defer c.revokeMu.Unlock()
	v := c.tokenView()
	children, _ := v.List("parent/" + hash + "/")
	for _, ch := range children {
		var te TokenEntry
		h := strings.TrimSuffix(ch, "/")
		if ok, _ := v.GetJSON("id/"+h, &te); ok {
			te.Parent = ""
			te.Orphan = true
			v.PutJSON("id/"+h, &te)
		}
	}
	v.DeletePrefix("parent/" + hash + "/")
	c.revokeOne(hash)
}

func (c *Core) revokeByPathPrefix(prefix string) {
	for _, k := range c.tokenView().Keys("id/") {
		var te TokenEntry
		if ok, _ := c.tokenView().GetJSON(k, &te); ok && strings.HasPrefix(te.Path, prefix) {
			c.revokeTree(te.IDHash)
		}
	}
}

func (c *Core) expirationLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	ticks := 0
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if c.barrier.Sealed() {
				return
			}
			ticks++
			if ticks%12 == 0 {
				c.runAutoRotate()
			}
			nowKey := fmt.Sprintf("expire/%020d/", time.Now().Unix())
			n := 0
			for _, k := range c.tokenView().Keys("expire/") {
				if k > nowKey {
					break
				}
				parts := strings.Split(k, "/")
				hash := parts[len(parts)-1]
				c.revokeTree(hash)
				c.tokenView().Delete(k)
				n++
			}
			if n > 0 {
				log.Printf("core: revoked %d expired token(s)", n)
			}
		}
	}
}

func (c *Core) renewToken(te *TokenEntry, increment time.Duration) error {
	if !te.Renewable {
		return badRequest("token is not renewable")
	}
	if increment <= 0 {
		increment = te.TTL
	}
	maxTTL := MaxTokenTTL
	if te.ExplicitMaxTTL > 0 && te.ExplicitMaxTTL < maxTTL {
		maxTTL = te.ExplicitMaxTTL
	}
	newExp := time.Now().Add(increment)
	if limit := te.CreationTime.Add(maxTTL); newExp.After(limit) {
		newExp = limit
	}
	if te.Parent != "" {
		if p, _ := c.lookupHash(te.Parent); p != nil && !p.ExpireTime.IsZero() && newExp.After(p.ExpireTime) {
			newExp = p.ExpireTime
		}
	}
	v := c.tokenView()
	if !te.ExpireTime.IsZero() {
		v.Delete(expireKey(te.ExpireTime, te.IDHash))
	}
	te.ExpireTime = newExp
	v.Put(expireKey(te.ExpireTime, te.IDHash), []byte{1})
	return v.PutJSON("id/"+te.IDHash, te)
}

func tokenData(te *TokenEntry) map[string]any {
	ttl := 0
	var exp any
	if !te.ExpireTime.IsZero() {
		ttl = int(time.Until(te.ExpireTime).Seconds())
		if ttl < 0 {
			ttl = 0
		}
		exp = te.ExpireTime
	}
	meta := te.Meta
	if meta == nil {
		meta = map[string]string{}
	}
	return map[string]any{
		"accessor": te.Accessor, "policies": te.Policies, "path": te.Path, "meta": meta,
		"display_name": te.DisplayName, "num_uses": te.NumUses, "creation_time": te.CreationTime.Unix(),
		"creation_ttl": int(te.TTL.Seconds()), "ttl": ttl, "expire_time": exp,
		"explicit_max_ttl": int(te.ExplicitMaxTTL.Seconds()), "renewable": te.Renewable,
		"orphan": te.Orphan, "type": te.Type, "id": "",
	}
}

func authFromEntry(te *TokenEntry, token string) *Auth {
	ttl := 0
	if !te.ExpireTime.IsZero() {
		ttl = int(time.Until(te.ExpireTime).Seconds())
	}
	return &Auth{
		ClientToken: token, Accessor: te.Accessor, Policies: te.Policies, TokenPolicies: te.Policies,
		Metadata: te.Meta, LeaseDuration: ttl, Renewable: te.Renewable, TokenType: te.Type,
		Orphan: te.Orphan, NumUses: te.NumUses,
	}
}

// issueLoginToken turns an auth backend's Auth into a real token.
func (c *Core) issueLoginToken(req *Request, resp *Response) error {
	a := resp.Auth
	pols := append([]string{}, a.Policies...)
	if !a.NoDefault {
		pols = append(pols, "default")
	}
	for _, p := range pols {
		if p == "root" {
			return badRequest("auth methods cannot issue root tokens")
		}
	}
	te := &TokenEntry{
		Policies: pols, Path: req.Path, Meta: a.Metadata, DisplayName: req.Mount.Type + "-" + a.DisplayName,
		TTL: a.TTL, ExplicitMaxTTL: a.MaxTTL, Renewable: true, Orphan: true,
	}
	te, token, err := c.createToken(te, nil)
	if err != nil {
		return err
	}
	resp.Auth = authFromEntry(te, token)
	return nil
}

// ---------------- auth/token backend ----------------

type tokenBackend struct{ c *Core }

func (b *tokenBackend) Handle(req *Request) (*Response, error) {
	c := b.c
	rel := req.RelPath
	switch {
	case rel == "create" || rel == "create-orphan":
		return b.create(req, rel == "create-orphan")
	case rel == "lookup-self":
		return &Response{Data: tokenData(req.TokenEntry)}, nil
	case rel == "lookup":
		te, err := c.LookupToken(dString(req.Data, "token"))
		if err != nil {
			return nil, err
		}
		if te == nil {
			return nil, badRequest("bad token")
		}
		return &Response{Data: tokenData(te)}, nil
	case rel == "lookup-accessor":
		te, err := c.lookupAccessor(dString(req.Data, "accessor"))
		if err != nil {
			return nil, err
		}
		if te == nil {
			return nil, badRequest("invalid accessor")
		}
		return &Response{Data: tokenData(te)}, nil
	case rel == "renew-self" || rel == "renew":
		te := req.TokenEntry
		if rel == "renew" {
			var err error
			te, err = c.LookupToken(dString(req.Data, "token"))
			if err != nil {
				return nil, err
			}
			if te == nil {
				return nil, badRequest("bad token")
			}
		}
		inc, err := dDuration(req.Data, "increment", 0)
		if err != nil {
			return nil, err
		}
		if err := c.renewToken(te, inc); err != nil {
			return nil, err
		}
		return &Response{Auth: authFromEntry(te, "")}, nil
	case rel == "revoke-self":
		c.revokeTree(req.TokenEntry.IDHash)
		return &Response{StatusCode: 204}, nil
	case rel == "revoke":
		te, _ := c.LookupToken(dString(req.Data, "token"))
		if te != nil {
			c.revokeTree(te.IDHash)
		}
		return &Response{StatusCode: 204}, nil
	case rel == "revoke-orphan":
		te, _ := c.LookupToken(dString(req.Data, "token"))
		if te != nil {
			c.revokeOrphan(te.IDHash)
		}
		return &Response{StatusCode: 204}, nil
	case rel == "revoke-accessor":
		te, _ := c.lookupAccessor(dString(req.Data, "accessor"))
		if te != nil {
			c.revokeTree(te.IDHash)
		}
		return &Response{StatusCode: 204}, nil
	case rel == "accessors" || rel == "accessors/":
		keys, _ := c.tokenView().List("accessor/")
		return listResponse(keys), nil
	}
	return nil, errCode(404, "unsupported path auth/token/%s", rel)
}

func (b *tokenBackend) create(req *Request, orphan bool) (*Response, error) {
	c := b.c
	parent := req.TokenEntry
	d := req.Data
	pols := dStrings(d, "policies")
	if len(pols) == 0 {
		pols = append([]string{}, parent.Policies...)
	}
	if !dBool(d, "no_default_policy", false) {
		pols = append(pols, "default")
	}
	if !parent.IsRoot() {
		allowed := map[string]bool{"default": true}
		for _, p := range parent.Policies {
			allowed[p] = true
		}
		for _, p := range pols {
			if !allowed[p] {
				return nil, errCode(403, "child policies must be a subset of the parent's policies (cannot grant %q)", p)
			}
		}
	}
	if !parent.IsRoot() {
		cleaned := pols[:0]
		for _, p := range pols {
			if p != "root" {
				cleaned = append(cleaned, p)
			}
		}
		pols = cleaned
	}
	ttl, err := dDuration(d, "ttl", 0)
	if err != nil {
		return nil, err
	}
	maxTTL, err := dDuration(d, "explicit_max_ttl", 0)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{}
	if m, ok := d["meta"].(map[string]any); ok {
		for k, v := range m {
			meta[k] = fmt.Sprint(v)
		}
	}
	name := dString(d, "display_name")
	if name == "" {
		name = "token"
	}
	te := &TokenEntry{
		Policies: pols, Path: req.Path, Meta: meta, DisplayName: "token-" + name,
		NumUses: dInt(d, "num_uses", 0), TTL: ttl, ExplicitMaxTTL: maxTTL,
		Renewable: dBool(d, "renewable", true), Orphan: orphan || dBool(d, "no_parent", false),
	}
	if te.Orphan && !orphan && !parent.IsRoot() && !req.ACL.Allowed(req.Path, true, CapUpdate, CapCreate) {
		return nil, errCode(403, "creating orphan tokens requires root or sudo")
	}
	if te.IsRoot() && ttl == 0 {
		te.TTL = 0
	}
	te, token, err := c.createToken(te, parent)
	if err != nil {
		return nil, err
	}
	return &Response{Auth: authFromEntry(te, token)}, nil
}
