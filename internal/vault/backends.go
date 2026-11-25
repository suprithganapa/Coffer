package vault

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---------------- cubbyhole ----------------

// cubbyholeBackend stores data scoped to the calling token; it is destroyed
// when the token is revoked.
type cubbyholeBackend struct{ view *View }

func (b *cubbyholeBackend) Handle(req *Request) (*Response, error) {
	if req.TokenEntry == nil {
		return nil, ErrPermissionDenied
	}
	v := b.view.Sub(req.TokenEntry.IDHash + "/")
	p := cleanPath(req.RelPath)
	if p == "response" || p == "info" || strings.HasPrefix(p, "response/") {
		return nil, badRequest("reserved cubbyhole path")
	}
	switch req.Operation {
	case OpList:
		prefix := ""
		if p != "" {
			prefix = p + "/"
		}
		keys, err := v.List("d/" + prefix)
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	case OpRead:
		var data map[string]any
		ok, err := v.GetJSON("d/"+p, &data)
		if err != nil || !ok {
			return nil, err
		}
		return &Response{Data: data}, nil
	case OpCreate, OpUpdate:
		if p == "" {
			return nil, badRequest("missing path")
		}
		return &Response{StatusCode: 204}, v.PutJSON("d/"+p, req.Data)
	case OpDelete:
		return &Response{StatusCode: 204}, v.Delete("d/" + p)
	}
	return nil, badRequest("unsupported operation")
}

// ---------------- TOTP ----------------

type totpKey struct {
	Key         []byte `json:"key"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"account_name"`
	Period      int    `json:"period"`
	Digits      int    `json:"digits"`
	Algorithm   string `json:"algorithm"`
	Skew        int    `json:"skew"`
	LastUsed    int64  `json:"last_used_counter"`
}

// totpBackend generates and validates time-based one-time passwords.
type totpBackend struct {
	view *View
	mu   sync.Mutex
}

func (k *totpKey) hasher() func() hash.Hash {
	switch k.Algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	}
	return sha1.New
}

func (k *totpKey) codeAt(counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	m := hmac.New(k.hasher(), k.Key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < k.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", k.Digits, v%mod)
}

func (b *totpBackend) Handle(req *Request) (*Response, error) {
	parts := strings.Split(strings.Trim(req.RelPath, "/"), "/")
	d := req.Data
	switch parts[0] {
	case "keys":
		if len(parts) == 1 {
			keys, err := b.view.List("key/")
			if err != nil {
				return nil, err
			}
			return listResponse(keys), nil
		}
		name := parts[1]
		switch req.Operation {
		case OpRead:
			var k totpKey
			ok, err := b.view.GetJSON("key/"+name, &k)
			if err != nil || !ok {
				return nil, err
			}
			return &Response{Data: map[string]any{"issuer": k.Issuer, "account_name": k.AccountName, "period": k.Period, "digits": k.Digits, "algorithm": k.Algorithm}}, nil
		case OpDelete:
			return &Response{StatusCode: 204}, b.view.Delete("key/" + name)
		case OpCreate, OpUpdate:
			k := totpKey{Issuer: dString(d, "issuer"), AccountName: dString(d, "account_name"), Period: dInt(d, "period", 30), Digits: dInt(d, "digits", 6), Algorithm: strings.ToUpper(dString(d, "algorithm")), Skew: dInt(d, "skew", 1)}
			if k.Algorithm == "" {
				k.Algorithm = "SHA1"
			}
			if k.Digits != 6 && k.Digits != 8 {
				return nil, badRequest("digits must be 6 or 8")
			}
			if k.Period < 1 {
				return nil, badRequest("period must be positive")
			}
			generate := dBool(d, "generate", false)
			out := map[string]any{}
			if generate {
				if k.AccountName == "" {
					return nil, badRequest("account_name is required when generating")
				}
				k.Key = randomBytes(20)
				secret := strings.TrimRight(base32.StdEncoding.EncodeToString(k.Key), "=")
				label := url.PathEscape(k.AccountName)
				if k.Issuer != "" {
					label = url.PathEscape(k.Issuer) + ":" + label
				}
				q := url.Values{"secret": {secret}, "algorithm": {k.Algorithm}, "digits": {fmt.Sprint(k.Digits)}, "period": {fmt.Sprint(k.Period)}}
				if k.Issuer != "" {
					q.Set("issuer", k.Issuer)
				}
				out["url"] = "otpauth://totp/" + label + "?" + q.Encode()
				out["secret"] = secret
			} else {
				raw := dString(d, "key")
				if u := dString(d, "url"); u != "" {
					pu, err := url.Parse(u)
					if err != nil {
						return nil, badRequest("invalid otpauth url")
					}
					raw = pu.Query().Get("secret")
					if a := pu.Query().Get("algorithm"); a != "" {
						k.Algorithm = strings.ToUpper(a)
					}
				}
				raw = strings.ToUpper(strings.ReplaceAll(raw, " ", ""))
				if pad := len(raw) % 8; pad != 0 {
					raw += strings.Repeat("=", 8-pad)
				}
				key, err := base32.StdEncoding.DecodeString(raw)
				if err != nil || len(key) == 0 {
					return nil, badRequest("key must be a base32 secret (or pass generate=true)")
				}
				k.Key = key
			}
			if err := b.view.PutJSON("key/"+name, k); err != nil {
				return nil, err
			}
			if len(out) == 0 {
				return &Response{StatusCode: 204}, nil
			}
			return &Response{Data: out}, nil
		}
	case "code":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		var k totpKey
		ok, err := b.view.GetJSON("key/"+parts[1], &k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, badRequest("unknown key")
		}
		counter := time.Now().Unix() / int64(k.Period)
		if req.Operation == OpRead {
			return &Response{Data: map[string]any{"code": k.codeAt(counter), "seconds_remaining": int64(k.Period) - time.Now().Unix()%int64(k.Period)}}, nil
		}
		code := dString(d, "code")
		for s := -k.Skew; s <= k.Skew; s++ {
			c := counter + int64(s)
			if subtle.ConstantTimeCompare([]byte(k.codeAt(c)), []byte(code)) == 1 {
				if c <= k.LastUsed {
					return &Response{Data: map[string]any{"valid": false, "reason": "code already used"}}, nil
				}
				k.LastUsed = c
				b.view.PutJSON("key/"+parts[1], k)
				return &Response{Data: map[string]any{"valid": true}}, nil
			}
		}
		return &Response{Data: map[string]any{"valid": false}}, nil
	}
	return nil, errCode(404, "unsupported totp path")
}

// ---------------- login lockout ----------------

type lockoutTracker struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLockoutTracker() *lockoutTracker { return &lockoutTracker{failures: map[string][]time.Time{}} }

const (
	lockoutThreshold = 5
	lockoutWindow    = 15 * time.Minute
)

func (l *lockoutTracker) locked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var keep []time.Time
	for _, t := range l.failures[key] {
		if time.Since(t) < lockoutWindow {
			keep = append(keep, t)
		}
	}
	l.failures[key] = keep
	return len(keep) >= lockoutThreshold
}

func (l *lockoutTracker) fail(key string) {
	l.mu.Lock()
	l.failures[key] = append(l.failures[key], time.Now())
	l.mu.Unlock()
}

func (l *lockoutTracker) clear(key string) {
	l.mu.Lock()
	delete(l.failures, key)
	l.mu.Unlock()
}

// ---------------- userpass ----------------

type userEntry struct {
	PasswordHash []byte        `json:"password_hash"`
	Salt         []byte        `json:"salt"`
	Policies     []string      `json:"policies"`
	TTL          time.Duration `json:"token_ttl"`
	MaxTTL       time.Duration `json:"token_max_ttl"`
	BoundCIDRs   []string      `json:"token_bound_cidrs"`
	CreatedAt    time.Time     `json:"created_at"`
}

const pbkdfIter = 120000

func hashPassword(pw string, salt []byte) []byte {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return k
}

type userpassBackend struct {
	c     *Core
	view  *View
	mount *MountEntry
}

func (b *userpassBackend) UnauthenticatedPaths() []string { return []string{"login/*"} }

func (b *userpassBackend) Exists(req *Request) (bool, error) {
	if strings.HasPrefix(req.RelPath, "users/") && strings.Count(req.RelPath, "/") == 1 {
		v, err := b.view.Get("user/" + strings.ToLower(strings.TrimPrefix(req.RelPath, "users/")))
		return v != nil, err
	}
	return true, nil
}

func cidrAllowed(cidrs []string, remote string) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
		if c == host {
			return true
		}
	}
	return false
}

func (b *userpassBackend) Handle(req *Request) (*Response, error) {
	parts := strings.Split(strings.Trim(req.RelPath, "/"), "/")
	d := req.Data
	switch parts[0] {
	case "login":
		if len(parts) < 2 {
			return nil, badRequest("username required: login/<username>")
		}
		name := strings.ToLower(parts[1])
		lockKey := b.mount.Accessor + "/" + name
		if b.c.lockouts.locked(lockKey) {
			return nil, errCode(429, "user is temporarily locked out after repeated failed logins; try again later")
		}
		var u userEntry
		ok, err := b.view.GetJSON("user/"+name, &u)
		if err != nil {
			return nil, err
		}
		pw := dString(d, "password")
		if !ok {
			hashPassword(pw, []byte("timing-equalizer")) // constant-ish timing
			b.c.lockouts.fail(lockKey)
			return nil, badRequest("invalid username or password")
		}
		if subtle.ConstantTimeCompare(hashPassword(pw, u.Salt), u.PasswordHash) != 1 {
			b.c.lockouts.fail(lockKey)
			return nil, badRequest("invalid username or password")
		}
		if !cidrAllowed(u.BoundCIDRs, req.RemoteAddr) {
			return nil, errCode(403, "login not permitted from this address")
		}
		b.c.lockouts.clear(lockKey)
		return &Response{Auth: &Auth{Policies: u.Policies, Metadata: map[string]string{"username": name}, TTL: u.TTL, MaxTTL: u.MaxTTL, DisplayName: name}}, nil
	case "users":
		if len(parts) == 1 {
			keys, err := b.view.List("user/")
			if err != nil {
				return nil, err
			}
			return listResponse(keys), nil
		}
		name := strings.ToLower(parts[1])
		if !policyNameRe.MatchString(name) {
			return nil, badRequest("invalid username")
		}
		var u userEntry
		exists, err := b.view.GetJSON("user/"+name, &u)
		if err != nil {
			return nil, err
		}
		if len(parts) == 3 {
			if !exists {
				return nil, badRequest("user %q not found", name)
			}
			switch parts[2] {
			case "password":
				pw := dString(d, "password")
				if len(pw) < 8 {
					return nil, badRequest("password must be at least 8 characters")
				}
				u.Salt = randomBytes(16)
				u.PasswordHash = hashPassword(pw, u.Salt)
			case "policies":
				u.Policies = uniqSorted(dStrings(d, "token_policies"))
				if has(d, "policies") {
					u.Policies = uniqSorted(dStrings(d, "policies"))
				}
			default:
				return nil, errCode(404, "unsupported path")
			}
			return &Response{StatusCode: 204}, b.view.PutJSON("user/"+name, u)
		}
		switch req.Operation {
		case OpRead:
			if !exists {
				return nil, nil
			}
			return &Response{Data: map[string]any{"token_policies": u.Policies, "policies": u.Policies, "token_ttl": int(u.TTL.Seconds()), "token_max_ttl": int(u.MaxTTL.Seconds()), "token_bound_cidrs": u.BoundCIDRs, "created_at": u.CreatedAt}}, nil
		case OpDelete:
			return &Response{StatusCode: 204}, b.view.Delete("user/" + name)
		case OpCreate, OpUpdate:
			if pw := dString(d, "password"); pw != "" {
				if len(pw) < 8 {
					return nil, badRequest("password must be at least 8 characters")
				}
				u.Salt = randomBytes(16)
				u.PasswordHash = hashPassword(pw, u.Salt)
			} else if !exists {
				return nil, badRequest("password is required")
			}
			if has(d, "policies") || has(d, "token_policies") {
				u.Policies = uniqSorted(append(dStrings(d, "policies"), dStrings(d, "token_policies")...))
			}
			if u.TTL, err = dDuration(d, "token_ttl", u.TTL); err != nil {
				return nil, err
			}
			if u.MaxTTL, err = dDuration(d, "token_max_ttl", u.MaxTTL); err != nil {
				return nil, err
			}
			if has(d, "token_bound_cidrs") {
				u.BoundCIDRs = dStrings(d, "token_bound_cidrs")
			}
			if !exists {
				u.CreatedAt = now()
			}
			return &Response{StatusCode: 204}, b.view.PutJSON("user/"+name, u)
		}
	}
	return nil, errCode(404, "unsupported userpass path %q", req.RelPath)
}

// ---------------- approle ----------------

type approleRole struct {
	RoleID          string        `json:"role_id"`
	Policies        []string      `json:"token_policies"`
	TTL             time.Duration `json:"token_ttl"`
	MaxTTL          time.Duration `json:"token_max_ttl"`
	SecretIDTTL     time.Duration `json:"secret_id_ttl"`
	SecretIDNumUses int           `json:"secret_id_num_uses"`
	BindSecretID    bool          `json:"bind_secret_id"`
	BoundCIDRs      []string      `json:"secret_id_bound_cidrs"`
}

type secretIDEntry struct {
	Accessor   string            `json:"accessor"`
	Created    time.Time         `json:"creation_time"`
	Expiration time.Time         `json:"expiration_time"`
	NumUses    int               `json:"num_uses"`
	Metadata   map[string]string `json:"metadata"`
}

type approleBackend struct {
	c     *Core
	view  *View
	mount *MountEntry
	mu    sync.Mutex
}

func (b *approleBackend) UnauthenticatedPaths() []string { return []string{"login"} }

func (b *approleBackend) Exists(req *Request) (bool, error) {
	parts := strings.Split(req.RelPath, "/")
	if len(parts) == 2 && parts[0] == "role" {
		v, err := b.view.Get("role/" + parts[1])
		return v != nil, err
	}
	return true, nil
}

func (b *approleBackend) secretHash(roleName, secret string) string {
	m := hmac.New(sha256.New, []byte(b.mount.UUID+roleName))
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

func (b *approleBackend) Handle(req *Request) (*Response, error) {
	parts := strings.Split(strings.Trim(req.RelPath, "/"), "/")
	d := req.Data
	if parts[0] == "login" {
		return b.login(req)
	}
	if parts[0] != "role" {
		return nil, errCode(404, "unsupported approle path %q", req.RelPath)
	}
	if len(parts) == 1 {
		keys, err := b.view.List("role/")
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	}
	name := parts[1]
	var r approleRole
	exists, err := b.view.GetJSON("role/"+name, &r)
	if err != nil {
		return nil, err
	}
	if len(parts) == 2 {
		switch req.Operation {
		case OpRead:
			if !exists {
				return nil, nil
			}
			return &Response{Data: map[string]any{"token_policies": r.Policies, "token_ttl": int(r.TTL.Seconds()), "token_max_ttl": int(r.MaxTTL.Seconds()), "secret_id_ttl": int(r.SecretIDTTL.Seconds()), "secret_id_num_uses": r.SecretIDNumUses, "bind_secret_id": r.BindSecretID, "secret_id_bound_cidrs": r.BoundCIDRs}}, nil
		case OpDelete:
			if exists {
				b.view.Delete("roleid/" + r.RoleID)
				b.view.DeletePrefix("secretid/" + name + "/")
			}
			return &Response{StatusCode: 204}, b.view.Delete("role/" + name)
		case OpCreate, OpUpdate:
			if !policyNameRe.MatchString(name) {
				return nil, badRequest("invalid role name")
			}
			if !exists {
				r = approleRole{RoleID: uuid(), BindSecretID: true}
			}
			if has(d, "policies") || has(d, "token_policies") {
				r.Policies = uniqSorted(append(dStrings(d, "policies"), dStrings(d, "token_policies")...))
			}
			if r.TTL, err = dDuration(d, "token_ttl", r.TTL); err != nil {
				return nil, err
			}
			if r.MaxTTL, err = dDuration(d, "token_max_ttl", r.MaxTTL); err != nil {
				return nil, err
			}
			if r.SecretIDTTL, err = dDuration(d, "secret_id_ttl", r.SecretIDTTL); err != nil {
				return nil, err
			}
			if has(d, "secret_id_num_uses") {
				r.SecretIDNumUses = dInt(d, "secret_id_num_uses", 0)
			}
			if has(d, "bind_secret_id") {
				r.BindSecretID = dBool(d, "bind_secret_id", true)
			}
			if has(d, "secret_id_bound_cidrs") {
				r.BoundCIDRs = dStrings(d, "secret_id_bound_cidrs")
			}
			if !r.BindSecretID && len(r.BoundCIDRs) == 0 {
				return nil, badRequest("bind_secret_id=false requires secret_id_bound_cidrs")
			}
			if err := b.view.Put("roleid/"+r.RoleID, []byte(name)); err != nil {
				return nil, err
			}
			return &Response{StatusCode: 204}, b.view.PutJSON("role/"+name, r)
		}
	}
	if !exists {
		return nil, badRequest("role %q not found", name)
	}
	switch parts[2] {
	case "role-id":
		if req.Operation == OpRead {
			return &Response{Data: map[string]any{"role_id": r.RoleID}}, nil
		}
		newID := dString(d, "role_id")
		if newID == "" {
			return nil, badRequest("role_id required")
		}
		b.view.Delete("roleid/" + r.RoleID)
		r.RoleID = newID
		b.view.Put("roleid/"+newID, []byte(name))
		return &Response{StatusCode: 204}, b.view.PutJSON("role/"+name, r)
	case "secret-id":
		if len(parts) == 4 && parts[3] == "destroy" {
			h := b.secretHash(name, dString(d, "secret_id"))
			var se secretIDEntry
			if ok, _ := b.view.GetJSON("secretid/"+name+"/"+h, &se); ok {
				b.view.Delete("accessor/" + name + "/" + se.Accessor)
			}
			return &Response{StatusCode: 204}, b.view.Delete("secretid/" + name + "/" + h)
		}
		if req.Operation == OpList || req.Operation == OpRead {
			keys, err := b.view.List("accessor/" + name + "/")
			if err != nil {
				return nil, err
			}
			return listResponse(keys), nil
		}
		secret := uuid()
		se := secretIDEntry{Accessor: uuid(), Created: now(), NumUses: r.SecretIDNumUses}
		if r.SecretIDTTL > 0 {
			se.Expiration = se.Created.Add(r.SecretIDTTL)
		}
		if m, ok := d["metadata"].(map[string]any); ok {
			se.Metadata = map[string]string{}
			for k, v := range m {
				se.Metadata[k] = fmt.Sprint(v)
			}
		}
		h := b.secretHash(name, secret)
		if err := b.view.PutJSON("secretid/"+name+"/"+h, se); err != nil {
			return nil, err
		}
		b.view.Put("accessor/"+name+"/"+se.Accessor, []byte(h))
		return &Response{Data: map[string]any{"secret_id": secret, "secret_id_accessor": se.Accessor, "secret_id_ttl": int(r.SecretIDTTL.Seconds()), "secret_id_num_uses": r.SecretIDNumUses}}, nil
	case "secret-id-accessor":
		if len(parts) == 4 && parts[3] == "destroy" {
			acc := dString(d, "secret_id_accessor")
			h, _ := b.view.Get("accessor/" + name + "/" + acc)
			if h != nil {
				b.view.Delete("secretid/" + name + "/" + string(h))
			}
			return &Response{StatusCode: 204}, b.view.Delete("accessor/" + name + "/" + acc)
		}
	}
	return nil, errCode(404, "unsupported approle path %q", req.RelPath)
}

func (b *approleBackend) login(req *Request) (*Response, error) {
	d := req.Data
	roleID := dString(d, "role_id")
	nameB, err := b.view.Get("roleid/" + roleID)
	if err != nil {
		return nil, err
	}
	if nameB == nil || roleID == "" {
		return nil, badRequest("invalid role_id or secret_id")
	}
	name := string(nameB)
	lockKey := b.mount.Accessor + "/" + name
	if b.c.lockouts.locked(lockKey) {
		return nil, errCode(429, "role is temporarily locked out after repeated failed logins")
	}
	var r approleRole
	if ok, err := b.view.GetJSON("role/"+name, &r); err != nil || !ok {
		return nil, badRequest("invalid role_id or secret_id")
	}
	if !cidrAllowed(r.BoundCIDRs, req.RemoteAddr) {
		return nil, errCode(403, "login not permitted from this address")
	}
	meta := map[string]string{"role_name": name}
	if r.BindSecretID {
		b.mu.Lock()
		defer b.mu.Unlock()
		h := b.secretHash(name, dString(d, "secret_id"))
		var se secretIDEntry
		ok, err := b.view.GetJSON("secretid/"+name+"/"+h, &se)
		if err != nil {
			return nil, err
		}
		if !ok || (!se.Expiration.IsZero() && time.Now().After(se.Expiration)) {
			if ok {
				b.view.Delete("secretid/" + name + "/" + h)
				b.view.Delete("accessor/" + name + "/" + se.Accessor)
			}
			b.c.lockouts.fail(lockKey)
			return nil, badRequest("invalid role_id or secret_id")
		}
		if se.NumUses > 0 {
			se.NumUses--
			if se.NumUses == 0 {
				b.view.Delete("secretid/" + name + "/" + h)
				b.view.Delete("accessor/" + name + "/" + se.Accessor)
			} else {
				b.view.PutJSON("secretid/"+name+"/"+h, se)
			}
		}
		for k, v := range se.Metadata {
			meta[k] = v
		}
	}
	b.c.lockouts.clear(lockKey)
	return &Response{Auth: &Auth{Policies: r.Policies, Metadata: meta, TTL: r.TTL, MaxTTL: r.MaxTTL, DisplayName: name}}, nil
}
