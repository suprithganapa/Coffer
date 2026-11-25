package vault

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"coffer/internal/shamir"
)

func (c *Core) handlePreSeal(req *Request) (*Response, error) {
	switch req.Path {
	case "sys/init":
		if req.Operation == OpRead {
			return &Response{Data: map[string]any{"initialized": c.Initialized()}}, nil
		}
		shares := dInt(req.Data, "secret_shares", 5)
		thr := dInt(req.Data, "secret_threshold", 3)
		res, err := c.Initialize(shares, thr)
		if err != nil {
			return nil, err
		}
		return &Response{Data: toMap(res)}, nil
	case "sys/seal-status":
		return &Response{Data: toMap(c.SealStatus())}, nil
	case "sys/unseal":
		st, err := c.Unseal(dString(req.Data, "key"), dBool(req.Data, "reset", false))
		if err != nil {
			return nil, err
		}
		return &Response{Data: toMap(st)}, nil
	case "sys/health":
		st := c.SealStatus()
		code := 200
		if !st.Initialized {
			code = 501
		} else if st.Sealed {
			code = 503
		}
		return &Response{StatusCode: code, Data: map[string]any{
			"initialized": st.Initialized, "sealed": st.Sealed, "standby": false,
			"version": Version, "cluster_name": c.ClusterName, "server_time_utc": time.Now().Unix(),
		}}, nil
	case "sys/leader":
		return &Response{Data: map[string]any{"ha_enabled": false, "is_self": true, "leader_address": ""}}, nil
	case "sys/generate-root":
		return c.generateRoot(req)
	}
	return nil, errCode(404, "unsupported path")
}

// collectRoot reconstructs and verifies the root key from submitted shares.
func (c *Core) collectRoot(keys []string) ([]byte, error) {
	sc, err := c.SealConfig()
	if err != nil || sc == nil {
		return nil, ErrNotInitialized
	}
	if len(keys) < sc.SecretThreshold {
		return nil, badRequest("need %d unseal keys, got %d", sc.SecretThreshold, len(keys))
	}
	var parts [][]byte
	for _, k := range keys {
		b, err := decodeKey(k)
		if err != nil {
			return nil, err
		}
		parts = append(parts, b)
	}
	root, err := c.combineKeys(parts, sc)
	if err != nil {
		return nil, badRequest("failed to combine keys: %v", err)
	}
	if !c.barrier.VerifyRoot(root) {
		return nil, badRequest("the provided unseal keys are invalid")
	}
	return root, nil
}

func (c *Core) generateRoot(req *Request) (*Response, error) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.barrier.Sealed() {
		return nil, ErrSealed
	}
	if _, err := c.collectRoot(dStrings(req.Data, "keys")); err != nil {
		return nil, err
	}
	te, token, err := c.createToken(&TokenEntry{Policies: []string{"root"}, DisplayName: "root", Path: "sys/generate-root"}, nil)
	if err != nil {
		return nil, err
	}
	return &Response{Data: map[string]any{"token": token, "accessor": te.Accessor}}, nil
}

func mountJSON(m MountEntry) map[string]any {
	opts := m.Options
	if opts == nil {
		opts = map[string]string{}
	}
	return map[string]any{
		"type": m.Type, "description": m.Description, "accessor": m.Accessor, "uuid": m.UUID,
		"options": opts, "system": m.System, "created_at": m.CreatedAt,
		"config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 0},
	}
}

func (c *Core) handleSys(req *Request) (*Response, error) {
	p := strings.TrimPrefix(req.Path, "sys/")
	op := req.Operation
	switch {
	case p == "seal":
		req.sealAfter = true
		return &Response{StatusCode: 204}, nil

	case p == "mounts" || p == "auth":
		auth := p == "auth"
		out := map[string]any{}
		for _, m := range c.Mounts(auth) {
			out[m.Path] = mountJSON(m)
		}
		return &Response{Data: out}, nil

	case strings.HasPrefix(p, "mounts/") || strings.HasPrefix(p, "auth/"):
		auth := strings.HasPrefix(p, "auth/")
		path := strings.TrimPrefix(strings.TrimPrefix(p, "mounts/"), "auth/")
		switch op {
		case OpRead:
			for _, m := range c.Mounts(auth) {
				if m.Path == normalizeMount(path) {
					return &Response{Data: mountJSON(m)}, nil
				}
			}
			return nil, errCode(404, "no mount at %q", path)
		case OpDelete:
			if err := c.Unmount(path, auth); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		case OpCreate, OpUpdate:
			typ := dString(req.Data, "type")
			if typ == "" {
				return nil, badRequest("type is required")
			}
			opts := map[string]string{}
			if o, ok := req.Data["options"].(map[string]any); ok {
				for k, v := range o {
					opts[k] = dString(map[string]any{"v": v}, "v")
				}
			}
			if err := c.Mount(path, typ, dString(req.Data, "description"), opts, auth); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		}

	case p == "policies/acl" || p == "policies/acl/" || p == "policy":
		return listResponse(c.ListPolicies()), nil

	case strings.HasPrefix(p, "policies/acl/") || strings.HasPrefix(p, "policy/"):
		name := strings.TrimPrefix(strings.TrimPrefix(p, "policies/acl/"), "policy/")
		switch op {
		case OpRead:
			if name == "root" {
				return &Response{Data: map[string]any{"name": "root", "policy": "# The root policy grants every capability on every path.\n"}}, nil
			}
			pol, err := c.GetPolicy(name)
			if err != nil {
				return nil, err
			}
			if pol == nil {
				return nil, errCode(404, "policy %q not found", name)
			}
			return &Response{Data: map[string]any{"name": pol.Name, "policy": pol.Raw, "rules": pol.Rules}}, nil
		case OpCreate, OpUpdate:
			raw := dString(req.Data, "policy")
			if raw == "" {
				raw = dString(req.Data, "rules")
			}
			if err := c.SetPolicy(name, raw); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		case OpDelete:
			if err := c.DeletePolicy(name); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		case OpList:
			return listResponse(c.ListPolicies()), nil
		}

	case p == "capabilities-self" || p == "capabilities" || p == "capabilities-accessor":
		te := req.TokenEntry
		if p == "capabilities" {
			t, err := c.LookupToken(dString(req.Data, "token"))
			if err != nil || t == nil {
				return nil, badRequest("invalid token")
			}
			te = t
		} else if p == "capabilities-accessor" {
			t, err := c.lookupAccessor(dString(req.Data, "accessor"))
			if err != nil || t == nil {
				return nil, badRequest("invalid accessor")
			}
			te = t
		}
		acl := c.ACLFor(te.Policies)
		paths := dStrings(req.Data, "paths")
		if pp := dString(req.Data, "path"); pp != "" {
			paths = append(paths, pp)
		}
		out := map[string]any{}
		var last []string
		for _, path := range paths {
			last = acl.Capabilities(strings.TrimPrefix(path, "/"))
			out[path] = last
		}
		if len(paths) == 1 {
			out["capabilities"] = last
		}
		return &Response{Data: out}, nil

	case p == "audit":
		out := map[string]any{}
		for _, d := range c.audit.List() {
			out[d.Path] = map[string]any{"type": d.Type, "description": d.Description, "options": d.Options, "path": d.Path}
		}
		return &Response{Data: out}, nil

	case strings.HasPrefix(p, "audit/"):
		name := strings.TrimPrefix(p, "audit/")
		switch op {
		case OpDelete:
			if err := c.audit.Disable(name); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		case OpCreate, OpUpdate:
			opts := map[string]string{}
			if o, ok := req.Data["options"].(map[string]any); ok {
				for k, v := range o {
					opts[k] = dString(map[string]any{"v": v}, "v")
				}
			}
			if err := c.audit.Enable(AuditDevice{Path: name, Type: dString(req.Data, "type"), Description: dString(req.Data, "description"), Options: opts}); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, nil
		}

	case p == "audit-events":
		evs := c.audit.Recent(dInt(req.Data, "limit", 200), dString(req.Data, "filter"))
		return &Response{Data: map[string]any{"events": evs}}, nil

	case p == "key-status":
		term, t := c.barrier.KeyStatus()
		return &Response{Data: map[string]any{"term": term, "install_time": t}}, nil

	case p == "rotate":
		term, err := c.barrier.Rotate()
		if err != nil {
			return nil, err
		}
		return &Response{Data: map[string]any{"term": term}}, nil

	case p == "rekey":
		return c.rekey(req)

	case p == "wrapping/wrap":
		if len(req.Data) == 0 {
			return nil, badRequest("no data to wrap")
		}
		if req.WrapTTL == 0 {
			req.WrapTTL = 5 * time.Minute
		}
		return &Response{Data: req.Data}, nil
	case p == "wrapping/unwrap":
		return c.unwrap(req)
	case p == "wrapping/lookup":
		return c.wrapLookup(req)

	case p == "internal/ui/mounts":
		acl := req.ACL
		sec := map[string]any{}
		for _, m := range c.Mounts(false) {
			if acl.AnyUnder(m.Path) {
				sec[m.Path] = mountJSON(m)
			}
		}
		au := map[string]any{}
		for _, m := range c.Mounts(true) {
			au[m.Path] = mountJSON(m)
		}
		return &Response{Data: map[string]any{"secret": sec, "auth": au}}, nil
	}

	for _, r := range c.sysRoute {
		if strings.HasPrefix(p, r.prefix) {
			return r.handler(req)
		}
	}
	return nil, errCode(404, "unsupported path sys/%s", p)
}

func (c *Core) rekey(req *Request) (*Response, error) {
	if _, err := c.collectRoot(dStrings(req.Data, "keys")); err != nil {
		return nil, err
	}
	shares := dInt(req.Data, "secret_shares", 5)
	thr := dInt(req.Data, "secret_threshold", 3)
	if shares < 1 || thr < 1 || thr > shares || shares > 255 || (shares > 1 && thr < 2) {
		return nil, badRequest("invalid seal configuration")
	}
	newRoot := randomBytes(32)
	var parts [][]byte
	if shares == 1 {
		parts = [][]byte{newRoot}
	} else {
		var err error
		if parts, err = shamir.Split(newRoot, shares, thr); err != nil {
			return nil, err
		}
	}
	if err := c.barrier.Rekey(newRoot); err != nil {
		return nil, err
	}
	sc, _ := c.SealConfig()
	sc.SecretShares, sc.SecretThreshold = shares, thr
	if err := c.store.Put(sealConfigPath, []byte(toJSON(sc))); err != nil {
		return nil, err
	}
	var hx, b64 []string
	for _, p := range parts {
		hx = append(hx, hex.EncodeToString(p))
		b64 = append(b64, base64.StdEncoding.EncodeToString(p))
	}
	return &Response{Data: map[string]any{"keys": hx, "keys_base64": b64, "secret_shares": shares, "secret_threshold": thr}}, nil
}

// ---------------- response wrapping ----------------

func (c *Core) cubbyPrefix() string {
	if m, _, _ := c.route("cubbyhole/"); m != nil {
		return "logical/" + m.UUID + "/"
	}
	return "logical/cubbyhole/"
}

func (c *Core) wrapResponse(req *Request, resp *Response) (*Response, error) {
	ttl := req.WrapTTL
	if ttl > 24*time.Hour*30 {
		ttl = 24 * time.Hour * 30
	}
	te, token, err := c.createToken(&TokenEntry{Policies: []string{wrappingPolicy}, DisplayName: "response-wrapping", NumUses: 1, TTL: ttl, Path: req.Path, Orphan: true}, nil)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"data": resp.Data, "warnings": resp.Warnings}
	if resp.Auth != nil {
		payload["auth"] = resp.Auth
	}
	v := c.barrier.View(c.cubbyPrefix() + te.IDHash + "/")
	if err := v.PutJSON("response", payload); err != nil {
		return nil, err
	}
	v.PutJSON("info", map[string]any{"creation_path": req.Path, "creation_time": te.CreationTime, "ttl": int(ttl.Seconds())})
	return &Response{WrapInfo: &WrapInfo{Token: token, Accessor: te.Accessor, TTL: int(ttl.Seconds()), CreationTime: te.CreationTime, CreationPath: req.Path}}, nil
}

func (c *Core) wrapTokenEntry(req *Request) (*TokenEntry, error) {
	te := req.TokenEntry
	if t := dString(req.Data, "token"); t != "" {
		var err error
		if te, err = c.LookupToken(t); err != nil {
			return nil, err
		}
	} else if te == nil && req.Token != "" {
		var err error
		if te, err = c.LookupToken(req.Token); err != nil {
			return nil, err
		}
	}
	if te == nil {
		return nil, badRequest("wrapping token is not valid or does not exist")
	}
	isWrap := false
	for _, p := range te.Policies {
		if p == wrappingPolicy {
			isWrap = true
		}
	}
	if !isWrap {
		return nil, badRequest("token is not a wrapping token")
	}
	return te, nil
}

func (c *Core) unwrap(req *Request) (*Response, error) {
	te, err := c.wrapTokenEntry(req)
	if err != nil {
		return nil, err
	}
	v := c.barrier.View(c.cubbyPrefix() + te.IDHash + "/")
	var payload struct {
		Data     map[string]any `json:"data"`
		Warnings []string       `json:"warnings"`
		Auth     *Auth          `json:"auth"`
	}
	ok, err := v.GetJSON("response", &payload)
	c.revokeTree(te.IDHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, badRequest("wrapping token is not valid or does not exist")
	}
	return &Response{Data: payload.Data, Warnings: payload.Warnings, Auth: payload.Auth}, nil
}

func (c *Core) wrapLookup(req *Request) (*Response, error) {
	te, err := c.wrapTokenEntry(req)
	if err != nil {
		return nil, err
	}
	var info map[string]any
	c.barrier.View(c.cubbyPrefix()+te.IDHash+"/").GetJSON("info", &info)
	return &Response{Data: info}, nil
}
