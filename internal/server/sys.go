package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"coffer/internal/filer"
	"coffer/internal/s3api"
	"coffer/internal/storage"
	"coffer/internal/vault"
)

func randAlnum(n int, alphabet string) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, _ := rand.Int(rand.Reader, max)
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func str(d map[string]any, k string) string {
	if v, ok := d[k].(string); ok {
		return v
	}
	if v, ok := d[k].(float64); ok {
		return strings.TrimSuffix(strings.TrimSuffix(big.NewFloat(v).Text('f', 6), "000000"), ".")
	}
	return ""
}

func strs(d map[string]any, k string) []string {
	var out []string
	switch v := d[k].(type) {
	case string:
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	case []any:
		for _, p := range v {
			if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

func num(d map[string]any, k string, def float64) float64 {
	switch v := d[k].(type) {
	case float64:
		return v
	case string:
		var f float64
		if _, err := fmtSscan(v, &f); err == nil {
			return f
		}
	}
	return def
}

func codeErr(code int, msg string) error { return &vault.CodedError{Code: code, Msg: msg} }

func (s *Server) registerSys() {
	s.Core.RegisterSys("storage/", false, s.sysStorage)
	s.Core.RegisterSys("storage/snapshot", true, s.sysSnapshot)
	s.Core.RegisterSys("s3/keys", false, s.sysS3Keys)
	s.Core.RegisterSys("shares", false, s.sysShares)
}

// ---------------- storage cluster ----------------

func (s *Server) fsStats() filer.Stats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if time.Since(s.statsAt) > 10*time.Second {
		s.statsVal = s.Filer.Stats()
		s.statsAt = time.Now()
	}
	return s.statsVal
}

func (s *Server) sysStorage(req *vault.Request) (*vault.Response, error) {
	p := strings.TrimPrefix(req.Path, "sys/storage/")
	switch p {
	case "status":
		st, err := s.Filer.Client.Status()
		out := map[string]any{"filer": s.fsStats(), "s3_port": s.cfg.S3Port, "region": s.cfg.Region}
		if err != nil {
			out["master_error"] = err.Error()
		} else {
			out["topology"] = st
		}
		return &vault.Response{Data: out}, nil
	case "grow":
		if req.Operation == vault.OpRead {
			return nil, codeErr(405, "use POST")
		}
		count := int(num(req.Data, "count", 1))
		u := "/vol/grow?count=" + itoa(count) + "&collection=" + qesc(str(req.Data, "collection")) + "&replication=" + qesc(str(req.Data, "replication")) + "&ttl=" + qesc(str(req.Data, "ttl"))
		var res map[string]any
		if err := s.Filer.Client.Call(u, &res); err != nil {
			return nil, codeErr(503, err.Error())
		}
		return &vault.Response{Data: res}, nil
	case "vacuum":
		if req.Operation == vault.OpRead {
			return nil, codeErr(405, "use POST")
		}
		th := num(req.Data, "garbage_threshold", 0.3)
		var res map[string]any
		if err := s.Filer.Client.Call("/vol/vacuum?garbageThreshold="+ftoa(th), &res); err != nil {
			return nil, codeErr(503, err.Error())
		}
		return &vault.Response{Data: res}, nil
	}
	return nil, codeErr(404, "unsupported path sys/storage/"+p+" (status, grow, vacuum)")
}

// ---------------- S3 access keys ----------------

type s3Key struct {
	AccessKey   string    `json:"access_key"`
	SecretKey   string    `json:"secret_key"`
	Policies    []string  `json:"policies"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type s3Creds struct {
	core  *vault.Core
	mu    sync.Mutex
	cache map[string]cachedKey
}

type cachedKey struct {
	id *s3api.Identity
	at time.Time
}

func (c *s3Creds) LookupAccessKey(ak string) (*s3api.Identity, error) {
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]cachedKey{}
	}
	if e, ok := c.cache[ak]; ok && time.Since(e.at) < 30*time.Second {
		c.mu.Unlock()
		return e.id, nil
	}
	c.mu.Unlock()
	if err := c.core.RLockUnsealed(); err != nil {
		return nil, err
	}
	defer c.core.RUnlock()
	var k s3Key
	ok, err := c.core.SysView("s3/").GetJSON("keys/"+ak, &k)
	if err != nil || !ok {
		return nil, err
	}
	id := &s3api.Identity{AccessKey: k.AccessKey, Secret: k.SecretKey, Token: &vault.TokenEntry{
		Policies: k.Policies, DisplayName: "s3-" + k.AccessKey, Accessor: "s3:" + k.AccessKey, Type: "s3",
	}}
	c.mu.Lock()
	c.cache[ak] = cachedKey{id, time.Now()}
	c.mu.Unlock()
	return id, nil
}

func (c *s3Creds) forget(ak string) {
	c.mu.Lock()
	delete(c.cache, ak)
	c.mu.Unlock()
}

var accessKeyRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{8,64}$`)

func (s *Server) sysS3Keys(req *vault.Request) (*vault.Response, error) {
	v := s.Core.SysView("s3/")
	rest := strings.Trim(strings.TrimPrefix(req.Path, "sys/s3/keys"), "/")
	creds := s.S3.Creds.(*s3Creds)
	if rest == "" {
		switch req.Operation {
		case vault.OpRead, vault.OpList:
			keys, _ := v.List("keys/")
			var out []map[string]any
			for _, ak := range keys {
				var k s3Key
				if ok, _ := v.GetJSON("keys/"+ak, &k); ok {
					out = append(out, map[string]any{"access_key": k.AccessKey, "policies": k.Policies, "description": k.Description, "created_by": k.CreatedBy, "created_at": k.CreatedAt})
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i]["access_key"].(string) < out[j]["access_key"].(string) })
			if out == nil {
				out = []map[string]any{}
			}
			return &vault.Response{Data: map[string]any{"keys": keys, "key_info": out}}, nil
		case vault.OpCreate, vault.OpUpdate:
			pols := strs(req.Data, "policies")
			if len(pols) == 0 {
				return nil, codeErr(400, "at least one policy is required")
			}
			te := req.TokenEntry
			if !te.IsRoot() {
				own := map[string]bool{}
				for _, p := range te.Policies {
					own[p] = true
				}
				for _, p := range pols {
					if !own[p] {
						return nil, codeErr(403, "you can only grant policies you hold yourself (cannot grant "+p+")")
					}
				}
			}
			for _, p := range pols {
				if p == "root" && !te.IsRoot() {
					return nil, codeErr(403, "only root can create root S3 keys")
				}
			}
			ak := str(req.Data, "access_key")
			if ak == "" {
				ak = "CFR" + randAlnum(17, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
			} else if !accessKeyRe.MatchString(ak) {
				return nil, codeErr(400, "access_key must be 8-64 characters of letters, digits, '-' or '_'")
			}
			if existing, _ := v.Get("keys/" + ak); existing != nil {
				return nil, codeErr(409, "access key already exists")
			}
			b := make([]byte, 30)
			rand.Read(b)
			k := s3Key{AccessKey: ak, SecretKey: base64.RawURLEncoding.EncodeToString(b), Policies: pols, Description: str(req.Data, "description"), CreatedBy: te.DisplayName, CreatedAt: time.Now().UTC()}
			if err := v.PutJSON("keys/"+ak, k); err != nil {
				return nil, err
			}
			return &vault.Response{Data: map[string]any{"access_key": k.AccessKey, "secret_key": k.SecretKey, "policies": k.Policies, "endpoint_port": s.cfg.S3Port, "region": s.cfg.Region}}, nil
		}
		return nil, codeErr(405, "unsupported operation")
	}
	ak := rest
	switch req.Operation {
	case vault.OpRead:
		var k s3Key
		ok, err := v.GetJSON("keys/"+ak, &k)
		if err != nil || !ok {
			return nil, err
		}
		return &vault.Response{Data: map[string]any{"access_key": k.AccessKey, "policies": k.Policies, "description": k.Description, "created_by": k.CreatedBy, "created_at": k.CreatedAt}}, nil
	case vault.OpDelete:
		creds.forget(ak)
		return &vault.Response{StatusCode: 204}, v.Delete("keys/" + ak)
	case vault.OpUpdate, vault.OpCreate:
		var k s3Key
		ok, err := v.GetJSON("keys/"+ak, &k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, codeErr(404, "access key not found")
		}
		if pols := strs(req.Data, "policies"); len(pols) > 0 {
			if !req.TokenEntry.IsRoot() {
				return nil, codeErr(403, "only root can change policies of an existing key")
			}
			k.Policies = pols
		}
		if d, ok := req.Data["description"].(string); ok {
			k.Description = d
		}
		creds.forget(ak)
		return &vault.Response{StatusCode: 204}, v.PutJSON("keys/"+ak, k)
	}
	return nil, codeErr(405, "unsupported operation")
}

// ---------------- share links ----------------

type share struct {
	ID           string    `json:"id"`
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxDownloads int       `json:"max_downloads"`
	Downloads    int       `json:"downloads"`
	URL          string    `json:"url,omitempty"`
}

var shareMu sync.Mutex

func (s *Server) createShare(p, ttl string, maxDl int, te *vault.TokenEntry) (*share, error) {
	e, err := s.Filer.Find(p)
	if err != nil {
		return nil, err
	}
	if e.IsDir {
		return nil, codeErr(400, "only files can be shared")
	}
	d := 24 * time.Hour
	if ttl != "" {
		if d, err = vault.ParseDuration(ttl); err != nil || d <= 0 {
			return nil, codeErr(400, "invalid ttl")
		}
	}
	if d > 30*24*time.Hour {
		return nil, codeErr(400, "share links can live at most 30 days")
	}
	if maxDl < 0 {
		maxDl = 0
	}
	if err := s.Core.RLockUnsealed(); err != nil {
		return nil, err
	}
	defer s.Core.RUnlock()
	sh := &share{ID: randAlnum(32, "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"), Path: p, Name: e.Name, CreatedBy: te.DisplayName, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(d), MaxDownloads: maxDl}
	if err := s.Core.SysView("shares/").PutJSON(sh.ID, sh); err != nil {
		return nil, err
	}
	sh.URL = s.ShareBase + "/share/" + sh.ID
	return sh, nil
}

func (s *Server) handleShareDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/share/")
	if len(id) != 32 {
		writeErrors(w, 404, "share link not found")
		return
	}
	if err := s.Core.RLockUnsealed(); err != nil {
		writeErrors(w, 503, "Coffer is sealed")
		return
	}
	shareMu.Lock()
	v := s.Core.SysView("shares/")
	var sh share
	ok, _ := v.GetJSON(id, &sh)
	if !ok || subtle.ConstantTimeCompare([]byte(sh.ID), []byte(id)) != 1 {
		shareMu.Unlock()
		s.Core.RUnlock()
		writeErrors(w, 404, "share link not found")
		return
	}
	if time.Now().After(sh.ExpiresAt) || (sh.MaxDownloads > 0 && sh.Downloads >= sh.MaxDownloads) {
		v.Delete(id)
		shareMu.Unlock()
		s.Core.RUnlock()
		writeErrors(w, 410, "share link expired")
		return
	}
	// count only full GETs, not HEAD/range probes
	if r.Method == http.MethodGet && r.Header.Get("Range") == "" {
		sh.Downloads++
		v.PutJSON(id, sh)
	}
	shareMu.Unlock()
	s.Core.RUnlock()
	e, err := s.Filer.Find(sh.Path)
	if err != nil || e.IsDir {
		writeErrors(w, 404, "shared file no longer exists")
		return
	}
	s.Core.AuditExternal("fs", nil, "share-download", sh.Path, r.RemoteAddr, 200, "", map[string]any{"share_id_hint": id[:6]})
	ct := e.Mime
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("Content-Disposition", contentDisposition(e.Name))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", e.Mtime, s.Filer.NewReader(e))
}

func (s *Server) sysShares(req *vault.Request) (*vault.Response, error) {
	v := s.Core.SysView("shares/")
	id := strings.Trim(strings.TrimPrefix(req.Path, "sys/shares"), "/")
	if id == "" {
		keys, _ := v.List("")
		var out []share
		for _, k := range keys {
			var sh share
			if ok, _ := v.GetJSON(k, &sh); ok {
				if time.Now().After(sh.ExpiresAt) {
					v.Delete(k)
					continue
				}
				// non-root users see only their own shares
				if !req.TokenEntry.IsRoot() && sh.CreatedBy != req.TokenEntry.DisplayName {
					continue
				}
				sh.URL = s.ShareBase + "/share/" + sh.ID
				out = append(out, sh)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
		if out == nil {
			out = []share{}
		}
		return &vault.Response{Data: map[string]any{"shares": out}}, nil
	}
	if req.Operation == vault.OpDelete {
		var sh share
		if ok, _ := v.GetJSON(id, &sh); ok && !req.TokenEntry.IsRoot() && sh.CreatedBy != req.TokenEntry.DisplayName {
			return nil, codeErr(403, "you can only revoke your own share links")
		}
		return &vault.Response{StatusCode: 204}, v.Delete(id)
	}
	return nil, codeErr(405, "unsupported operation")
}

var _ = storage.ParseTTL
