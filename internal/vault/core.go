// Package vault is Coffer's secrets core: an encrypted barrier sealed with
// Shamir key shares, token authentication, path-based ACL policies, pluggable
// auth methods and secrets engines, response wrapping and audit logging.
package vault

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"coffer/internal/kvstore"
	"coffer/internal/shamir"
)

const Version = "1.0.0"

// Operation names
const (
	OpRead   = "read"
	OpList   = "list"
	OpCreate = "create"
	OpUpdate = "update"
	OpPatch  = "patch"
	OpDelete = "delete"
)

// Request is a logical request routed through the core.
type Request struct {
	ID         string
	Operation  string
	Path       string
	Data       map[string]any
	Token      string
	RemoteAddr string
	Headers    http.Header
	WrapTTL    time.Duration

	// filled during routing
	TokenEntry *TokenEntry
	ACL        *ACL
	MountPath  string // e.g. "secret/" or "auth/userpass/"
	RelPath    string // path relative to the mount
	View       *View
	Mount      *MountEntry
	core       *Core
	sealAfter  bool
}

// Auth is returned by login endpoints.
type Auth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	TokenType     string            `json:"token_type"`
	Orphan        bool              `json:"orphan"`
	NumUses       int               `json:"num_uses"`

	// inputs from auth backends (not serialized)
	TTL         time.Duration `json:"-"`
	MaxTTL      time.Duration `json:"-"`
	DisplayName string        `json:"-"`
	NoDefault   bool          `json:"-"`
}

// RawResponse is used for non-JSON payloads (e.g. PEM certificates).
type RawResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// WrapInfo describes a wrapped response.
type WrapInfo struct {
	Token        string    `json:"token"`
	Accessor     string    `json:"accessor"`
	TTL          int       `json:"ttl"`
	CreationTime time.Time `json:"creation_time"`
	CreationPath string    `json:"creation_path"`
}

// Response from a backend.
type Response struct {
	Data          map[string]any
	Auth          *Auth
	Warnings      []string
	StatusCode    int
	Raw           *RawResponse
	WrapInfo      *WrapInfo
	LeaseDuration int
	Renewable     bool
}

// Backend is a secrets engine or auth method.
type Backend interface {
	Handle(req *Request) (*Response, error)
}

// ExistenceChecker lets the core pick create vs update capability.
type ExistenceChecker interface {
	Exists(req *Request) (bool, error)
}

// UnauthPather declares mount-relative paths that need no token.
type UnauthPather interface {
	UnauthenticatedPaths() []string
}

// MountEntry is a mounted backend.
type MountEntry struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	UUID        string            `json:"uuid"`
	Accessor    string            `json:"accessor"`
	Options     map[string]string `json:"options"`
	System      bool              `json:"system"`
	CreatedAt   time.Time         `json:"created_at"`
	backend     Backend
}

// SysHandler handles extra sys/ paths registered by other subsystems.
type SysHandler func(req *Request) (*Response, error)

type sysRoute struct {
	prefix  string
	handler SysHandler
	sudo    bool
}

// SealConfig is stored in plaintext.
type SealConfig struct {
	SecretShares    int       `json:"secret_shares"`
	SecretThreshold int       `json:"secret_threshold"`
	InitializedAt   time.Time `json:"initialized_at"`
}

// Core ties everything together.
type Core struct {
	store   *kvstore.Store
	barrier *Barrier

	stateMu    sync.RWMutex
	unsealMu   sync.Mutex
	unsealKeys [][]byte
	unsealing  bool

	mountsMu sync.RWMutex
	mounts   map[string]*MountEntry // "secret/"
	auths    map[string]*MountEntry // "userpass/"

	policyMu    sync.RWMutex
	policyCache map[string]*Policy

	audit    *AuditBroker
	stopCh   chan struct{}
	sysRoute []sysRoute

	OnUnseal []func()
	OnSeal   []func()

	ClusterName string
	lockouts    *lockoutTracker
	revokeMu    sync.Mutex
}

// NewCore opens the secrets core over a kvstore.
func NewCore(store *kvstore.Store) *Core {
	c := &Core{
		store: store, barrier: NewBarrier(store),
		mounts: map[string]*MountEntry{}, auths: map[string]*MountEntry{},
		policyCache: map[string]*Policy{}, ClusterName: "coffer-cluster",
		lockouts: newLockoutTracker(),
	}
	c.audit = newAuditBroker(c)
	return c
}

// RegisterSys adds a handler for sys/<prefix>*.
func (c *Core) RegisterSys(prefix string, sudo bool, h SysHandler) {
	c.sysRoute = append(c.sysRoute, sysRoute{prefix: prefix, handler: h, sudo: sudo})
	sort.Slice(c.sysRoute, func(i, j int) bool { return len(c.sysRoute[i].prefix) > len(c.sysRoute[j].prefix) })
}

func (c *Core) Barrier() *Barrier { return c.barrier }

// ---------------- init / seal / unseal ----------------

func (c *Core) Initialized() bool { return c.barrier.Initialized() }
func (c *Core) Sealed() bool      { return c.barrier.Sealed() }

func (c *Core) SealConfig() (*SealConfig, error) {
	raw, ok := c.store.Get(sealConfigPath)
	if !ok {
		return nil, nil
	}
	var sc SealConfig
	return &sc, json.Unmarshal(raw, &sc)
}

// InitResult is returned once at initialization.
type InitResult struct {
	Keys      []string `json:"keys"`
	KeysB64   []string `json:"keys_base64"`
	RootToken string   `json:"root_token"`
	Shares    int      `json:"secret_shares"`
	Threshold int      `json:"secret_threshold"`
}

// Initialize creates the barrier, unseal keys and the initial root token.
func (c *Core) Initialize(shares, threshold int) (*InitResult, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.barrier.Initialized() {
		return nil, badRequest("Coffer is already initialized")
	}
	if shares < 1 || threshold < 1 || threshold > shares || shares > 255 {
		return nil, badRequest("invalid seal configuration: need 1 <= threshold <= shares <= 255")
	}
	if shares > 1 && threshold < 2 {
		return nil, badRequest("threshold must be at least 2 when using more than one share")
	}
	rootKey := randomBytes(32)
	var parts [][]byte
	if shares == 1 {
		parts = [][]byte{rootKey}
	} else {
		var err error
		parts, err = shamir.Split(rootKey, shares, threshold)
		if err != nil {
			return nil, err
		}
	}
	if err := c.barrier.Initialize(rootKey); err != nil {
		return nil, err
	}
	sc, _ := json.Marshal(SealConfig{SecretShares: shares, SecretThreshold: threshold, InitializedAt: now()})
	if err := c.store.Put(sealConfigPath, sc); err != nil {
		return nil, err
	}
	if err := c.barrier.Unseal(rootKey); err != nil {
		return nil, err
	}
	defer c.barrier.Seal()
	if err := c.setupDefaults(); err != nil {
		return nil, err
	}
	te, token, err := c.createToken(&TokenEntry{Policies: []string{"root"}, DisplayName: "root", Path: "sys/init"}, nil)
	if err != nil {
		return nil, err
	}
	_ = te
	res := &InitResult{RootToken: token, Shares: shares, Threshold: threshold}
	for _, p := range parts {
		res.Keys = append(res.Keys, hex.EncodeToString(p))
		res.KeysB64 = append(res.KeysB64, base64.StdEncoding.EncodeToString(p))
	}
	log.Printf("core: initialized with %d share(s), threshold %d", shares, threshold)
	return res, nil
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, badRequest("unseal key must be hex or base64")
}

// SealStatus is reported by sys/seal-status.
type SealStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	StorageType string `json:"storage_type"`
}

func (c *Core) SealStatus() SealStatus {
	st := SealStatus{Type: "shamir", Initialized: c.Initialized(), Sealed: c.Sealed(), Version: Version, ClusterName: c.ClusterName, StorageType: "coffer-kv"}
	if sc, _ := c.SealConfig(); sc != nil {
		st.T, st.N = sc.SecretThreshold, sc.SecretShares
	}
	c.unsealMu.Lock()
	st.Progress = len(c.unsealKeys)
	c.unsealMu.Unlock()
	return st
}

// combineKeys reconstructs the root key from shares.
func (c *Core) combineKeys(parts [][]byte, sc *SealConfig) ([]byte, error) {
	if sc.SecretShares == 1 {
		return parts[0], nil
	}
	return shamir.Combine(parts)
}

// Unseal submits one key share. Returns the resulting status.
func (c *Core) Unseal(key string, reset bool) (SealStatus, error) {
	if reset {
		c.unsealMu.Lock()
		c.unsealKeys = nil
		c.unsealMu.Unlock()
		return c.SealStatus(), nil
	}
	if !c.Initialized() {
		return c.SealStatus(), ErrNotInitialized
	}
	if !c.Sealed() {
		return c.SealStatus(), nil
	}
	k, err := decodeKey(key)
	if err != nil {
		return c.SealStatus(), err
	}
	sc, err := c.SealConfig()
	if err != nil || sc == nil {
		return c.SealStatus(), errors.New("seal configuration missing")
	}
	c.unsealMu.Lock()
	for _, existing := range c.unsealKeys {
		if string(existing) == string(k) {
			c.unsealMu.Unlock()
			return c.SealStatus(), nil // duplicate share, ignore
		}
	}
	c.unsealKeys = append(c.unsealKeys, k)
	if len(c.unsealKeys) < sc.SecretThreshold {
		c.unsealMu.Unlock()
		return c.SealStatus(), nil
	}
	parts := c.unsealKeys
	c.unsealKeys = nil
	c.unsealMu.Unlock()

	root, err := c.combineKeys(parts, sc)
	if err != nil {
		return c.SealStatus(), badRequest("failed to combine unseal keys: %v", err)
	}
	c.stateMu.Lock()
	if err := c.barrier.Unseal(root); err != nil {
		c.stateMu.Unlock()
		return c.SealStatus(), badRequest("%v", err)
	}
	if err := c.postUnseal(); err != nil {
		c.barrier.Seal()
		c.stateMu.Unlock()
		return c.SealStatus(), err
	}
	c.stateMu.Unlock()
	log.Printf("core: unsealed")
	for _, f := range c.OnUnseal {
		go f()
	}
	return c.SealStatus(), nil
}

// UnsealWithRoot is used in dev mode / tests.
func (c *Core) UnsealWithKeys(keys []string) error {
	for _, k := range keys {
		st, err := c.Unseal(k, false)
		if err != nil {
			return err
		}
		if !st.Sealed {
			return nil
		}
	}
	if c.Sealed() {
		return errors.New("not enough keys to unseal")
	}
	return nil
}

// Seal locks the core: keys are wiped and all requests fail until unsealed.
func (c *Core) Seal() {
	for _, f := range c.OnSeal {
		f()
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.barrier.Sealed() {
		return
	}
	if c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
	c.mountsMu.Lock()
	c.mounts = map[string]*MountEntry{}
	c.auths = map[string]*MountEntry{}
	c.mountsMu.Unlock()
	c.policyMu.Lock()
	c.policyCache = map[string]*Policy{}
	c.policyMu.Unlock()
	c.audit.reset()
	c.barrier.Seal()
	log.Printf("core: sealed")
}

func (c *Core) setupDefaults() error {
	if ok, _ := c.sysView().GetJSON("mounts", &[]MountEntry{}); ok {
		return nil
	}
	ms := []MountEntry{
		{Path: "cubbyhole/", Type: "cubbyhole", Description: "per-token private secret storage", System: true},
		{Path: "secret/", Type: "kv-v2", Description: "key/value secret storage (versioned)"},
		{Path: "transit/", Type: "transit", Description: "encryption as a service; also protects encrypted folders and buckets", System: true},
		{Path: "pki/", Type: "pki", Description: "X.509 certificate authority"},
	}
	for i := range ms {
		ms[i].UUID, ms[i].Accessor, ms[i].CreatedAt = uuid(), ms[i].Type+"_"+randomString(8), now()
	}
	as := []MountEntry{
		{Path: "token/", Type: "token", Description: "token based credentials", System: true},
		{Path: "userpass/", Type: "userpass", Description: "username & password login"},
	}
	for i := range as {
		as[i].UUID, as[i].Accessor, as[i].CreatedAt = uuid(), "auth_"+as[i].Type+"_"+randomString(8), now()
	}
	if err := c.sysView().PutJSON("mounts", ms); err != nil {
		return err
	}
	if err := c.sysView().PutJSON("auth", as); err != nil {
		return err
	}
	return c.sysView().PutJSON("policy/default", map[string]string{"name": "default", "policy": DefaultPolicy})
}

func (c *Core) sysView() *View { return c.barrier.View("sys/") }

// postUnseal loads tables; caller holds stateMu.
func (c *Core) postUnseal() error {
	if err := c.setupDefaults(); err != nil {
		return err
	}
	var ms, as []MountEntry
	if _, err := c.sysView().GetJSON("mounts", &ms); err != nil {
		return err
	}
	if _, err := c.sysView().GetJSON("auth", &as); err != nil {
		return err
	}
	c.mountsMu.Lock()
	c.mounts = map[string]*MountEntry{}
	c.auths = map[string]*MountEntry{}
	for i := range ms {
		m := ms[i]
		b, err := c.newBackend(&m, false)
		if err != nil {
			log.Printf("core: skipping mount %s: %v", m.Path, err)
			continue
		}
		m.backend = b
		c.mounts[m.Path] = &m
	}
	for i := range as {
		m := as[i]
		b, err := c.newBackend(&m, true)
		if err != nil {
			log.Printf("core: skipping auth mount %s: %v", m.Path, err)
			continue
		}
		m.backend = b
		c.auths[m.Path] = &m
	}
	c.mountsMu.Unlock()
	if err := c.audit.load(); err != nil {
		log.Printf("core: audit load: %v", err)
	}
	c.stopCh = make(chan struct{})
	go c.expirationLoop(c.stopCh)
	return nil
}

// ---------------- mounts ----------------

var mountPathRe = regexp.MustCompile(`^[A-Za-z0-9_\-.]+(/[A-Za-z0-9_\-.]+)*/$`)

var reservedMounts = []string{"sys/", "auth/", "fs/", "identity/", "cubbyhole/"}

func normalizeMount(p string) string {
	p = strings.Trim(p, "/")
	return p + "/"
}

func (c *Core) newBackend(m *MountEntry, auth bool) (Backend, error) {
	prefix := "logical/" + m.UUID + "/"
	if auth {
		prefix = "auth/" + m.UUID + "/"
	}
	view := c.barrier.View(prefix)
	if auth {
		switch m.Type {
		case "token":
			return &tokenBackend{c: c}, nil
		case "userpass":
			return &userpassBackend{c: c, view: view, mount: m}, nil
		case "approle":
			return &approleBackend{c: c, view: view, mount: m}, nil
		}
		return nil, badRequest("unknown auth method type %q (supported: userpass, approle)", m.Type)
	}
	switch m.Type {
	case "kv-v2":
		return &kvBackend{view: view, v2: true}, nil
	case "kv":
		return &kvBackend{view: view, v2: m.Options["version"] == "2"}, nil
	case "transit":
		return &transitBackend{view: view}, nil
	case "pki":
		return &pkiBackend{view: view, mount: m}, nil
	case "cubbyhole":
		return &cubbyholeBackend{view: view}, nil
	case "totp":
		return &totpBackend{view: view}, nil
	}
	return nil, badRequest("unknown secrets engine type %q (supported: kv, kv-v2, transit, pki, totp)", m.Type)
}

func (c *Core) persistMountsLocked(auth bool) error {
	src := c.mounts
	key := "mounts"
	if auth {
		src, key = c.auths, "auth"
	}
	list := make([]MountEntry, 0, len(src))
	for _, m := range src {
		list = append(list, *m)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	return c.sysView().PutJSON(key, list)
}

// Mount enables a secrets engine or auth method.
func (c *Core) Mount(path, typ, desc string, opts map[string]string, auth bool) error {
	path = normalizeMount(path)
	if !mountPathRe.MatchString(path) {
		return badRequest("invalid mount path %q", path)
	}
	if !auth {
		for _, r := range reservedMounts {
			if strings.HasPrefix(path, r) || strings.HasPrefix(r, path) {
				return badRequest("cannot mount at reserved path %q", path)
			}
		}
		if typ == "cubbyhole" || typ == "token" {
			return badRequest("type %q cannot be mounted again", typ)
		}
	} else if typ == "token" {
		return badRequest("the token auth method is always enabled")
	}
	c.mountsMu.Lock()
	defer c.mountsMu.Unlock()
	table := c.mounts
	if auth {
		table = c.auths
	}
	for existing := range table {
		if strings.HasPrefix(existing, path) || strings.HasPrefix(path, existing) {
			return badRequest("path %q conflicts with existing mount %q", path, existing)
		}
	}
	if opts == nil {
		opts = map[string]string{}
	}
	m := &MountEntry{Path: path, Type: typ, Description: desc, UUID: uuid(), Options: opts, CreatedAt: now()}
	if auth {
		m.Accessor = "auth_" + typ + "_" + randomString(8)
	} else {
		m.Accessor = typ + "_" + randomString(8)
	}
	b, err := c.newBackend(m, auth)
	if err != nil {
		return err
	}
	m.backend = b
	table[path] = m
	if err := c.persistMountsLocked(auth); err != nil {
		delete(table, path)
		return err
	}
	return nil
}

// Unmount disables a mount and destroys its data.
func (c *Core) Unmount(path string, auth bool) error {
	path = normalizeMount(path)
	c.mountsMu.Lock()
	table := c.mounts
	if auth {
		table = c.auths
	}
	m, ok := table[path]
	if !ok {
		c.mountsMu.Unlock()
		return errCode(404, "no mount at %q", path)
	}
	if m.System {
		c.mountsMu.Unlock()
		return badRequest("mount %q is required by the system and cannot be disabled", path)
	}
	delete(table, path)
	if err := c.persistMountsLocked(auth); err != nil {
		table[path] = m
		c.mountsMu.Unlock()
		return err
	}
	c.mountsMu.Unlock()
	prefix := "logical/" + m.UUID + "/"
	if auth {
		prefix = "auth/" + m.UUID + "/"
		c.revokeByPathPrefix("auth/" + path)
	}
	return c.barrier.DeletePrefix(prefix)
}

// Mounts returns copies of the mount tables.
func (c *Core) Mounts(auth bool) []MountEntry {
	c.mountsMu.RLock()
	defer c.mountsMu.RUnlock()
	src := c.mounts
	if auth {
		src = c.auths
	}
	out := make([]MountEntry, 0, len(src))
	for _, m := range src {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (c *Core) route(path string) (*MountEntry, string, bool) {
	c.mountsMu.RLock()
	defer c.mountsMu.RUnlock()
	auth := false
	table := c.mounts
	p := path
	if strings.HasPrefix(path, "auth/") {
		auth = true
		table = c.auths
		p = strings.TrimPrefix(path, "auth/")
	}
	var best *MountEntry
	for mp, m := range table {
		if (strings.HasPrefix(p, mp) || p+"/" == mp) && (best == nil || len(mp) > len(best.Path)) {
			best = m
		}
	}
	if best == nil {
		return nil, "", auth
	}
	rel := strings.TrimPrefix(p, best.Path)
	if p+"/" == best.Path {
		rel = ""
	}
	return best, rel, auth
}

// ---------------- policies ----------------

func (c *Core) GetPolicy(name string) (*Policy, error) {
	if name == "root" {
		return &Policy{Name: "root"}, nil
	}
	if name == wrappingPolicy {
		return ParsePolicy(name, `path "sys/wrapping/unwrap" { capabilities = ["update"] }
path "sys/wrapping/lookup" { capabilities = ["update"] }`)
	}
	c.policyMu.RLock()
	p, ok := c.policyCache[name]
	c.policyMu.RUnlock()
	if ok {
		return p, nil
	}
	var stored struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
	}
	found, err := c.sysView().GetJSON("policy/"+name, &stored)
	if err != nil || !found {
		return nil, err
	}
	p, err = ParsePolicy(name, stored.Policy)
	if err != nil {
		return nil, err
	}
	c.policyMu.Lock()
	c.policyCache[name] = p
	c.policyMu.Unlock()
	return p, nil
}

var policyNameRe = regexp.MustCompile(`^[A-Za-z0-9_\-.]+$`)

func (c *Core) SetPolicy(name, raw string) error {
	name = strings.ToLower(name)
	if name == "root" {
		return badRequest("cannot update the root policy")
	}
	if name == "response-wrapping" {
		return badRequest("cannot update a reserved policy")
	}
	if !policyNameRe.MatchString(name) {
		return badRequest("invalid policy name")
	}
	if _, err := ParsePolicy(name, raw); err != nil {
		return badRequest("failed to parse policy: %v", err)
	}
	if err := c.sysView().PutJSON("policy/"+name, map[string]string{"name": name, "policy": raw}); err != nil {
		return err
	}
	c.policyMu.Lock()
	delete(c.policyCache, name)
	c.policyMu.Unlock()
	return nil
}

func (c *Core) DeletePolicy(name string) error {
	if name == "root" || name == "default" {
		return badRequest("cannot delete the %s policy", name)
	}
	c.policyMu.Lock()
	delete(c.policyCache, name)
	c.policyMu.Unlock()
	return c.sysView().Delete("policy/" + name)
}

func (c *Core) ListPolicies() []string {
	keys, _ := c.sysView().List("policy/")
	out := append([]string{"root"}, keys...)
	return uniqSorted(out)
}

// ACLFor builds the ACL for a set of policy names.
func (c *Core) ACLFor(names []string) *ACL {
	var ps []*Policy
	for _, n := range names {
		if p, err := c.GetPolicy(n); err == nil && p != nil {
			ps = append(ps, p)
		}
	}
	return NewACL(ps)
}

// ---------------- request handling ----------------

var preSealPaths = map[string]bool{"sys/init": true, "sys/seal-status": true, "sys/unseal": true, "sys/health": true, "sys/generate-root": true, "sys/leader": true}

func (c *Core) isUnauth(req *Request, m *MountEntry, rel string) bool {
	switch req.Path {
	case "sys/wrapping/unwrap", "sys/wrapping/lookup":
		return req.Token == "" || dString(req.Data, "token") != ""
	}
	if m == nil {
		return false
	}
	if up, ok := m.backend.(UnauthPather); ok {
		for _, p := range up.UnauthenticatedPaths() {
			if matchPattern(p, rel) {
				return true
			}
		}
	}
	return false
}

// HandleRequest is the single entry point for logical requests.
func (c *Core) HandleRequest(req *Request) (resp *Response, retErr error) {
	req.ID = uuid()
	req.core = c
	req.Path = strings.TrimPrefix(req.Path, "/")
	if req.Data == nil {
		req.Data = map[string]any{}
	}
	if preSealPaths[req.Path] {
		resp, retErr = c.handlePreSeal(req)
		c.audit.logRequest(req, resp, retErr)
		return
	}
	c.stateMu.RLock()
	defer func() {
		c.stateMu.RUnlock()
		if req.sealAfter {
			c.Seal()
		}
	}()
	if !c.Initialized() {
		return nil, ErrNotInitialized
	}
	if c.barrier.Sealed() {
		return nil, ErrSealed
	}

	var mount *MountEntry
	var rel string
	isSys := strings.HasPrefix(req.Path, "sys/") || req.Path == "sys"
	if !isSys {
		m, r, _ := c.route(req.Path)
		if m == nil {
			return nil, errCode(404, "no handler for route %q", req.Path)
		}
		mount, rel = m, r
		req.Mount, req.RelPath = m, r
		if strings.HasPrefix(req.Path, "auth/") {
			req.MountPath = "auth/" + m.Path
			req.View = c.barrier.View("auth/" + m.UUID + "/")
		} else {
			req.MountPath = m.Path
			req.View = c.barrier.View("logical/" + m.UUID + "/")
		}
	}

	if !c.isUnauth(req, mount, rel) {
		te, err := c.LookupToken(req.Token)
		if err != nil {
			return nil, err
		}
		if te == nil {
			err := errCode(403, "permission denied (invalid or expired token)")
			c.audit.logRequest(req, nil, err)
			return nil, err
		}
		req.TokenEntry = te
		req.ACL = c.ACLFor(te.Policies)
		if err := c.authorize(req, mount); err != nil {
			c.audit.logRequest(req, nil, err)
			return nil, err
		}
		if te.NumUses > 0 {
			last, err := c.useToken(te)
			if err != nil {
				return nil, err
			}
			if last {
				defer c.revokeTree(te.IDHash)
			}
		}
	}

	if isSys {
		resp, retErr = c.handleSys(req)
	} else {
		resp, retErr = mount.backend.Handle(req)
	}
	if retErr == nil && resp != nil && resp.Auth != nil && resp.Auth.ClientToken == "" && strings.HasPrefix(req.Path, "auth/") {
		retErr = c.issueLoginToken(req, resp)
	}
	if retErr == nil && req.WrapTTL > 0 && resp != nil && resp.Raw == nil {
		resp, retErr = c.wrapResponse(req, resp)
	}
	c.audit.logRequest(req, resp, retErr)
	return resp, retErr
}

// requiredCaps maps an operation to the capabilities that satisfy it.
func (c *Core) requiredCaps(req *Request, mount *MountEntry) []string {
	switch req.Operation {
	case OpRead:
		return []string{CapRead}
	case OpList:
		return []string{CapList}
	case OpDelete:
		return []string{CapDelete}
	case OpPatch:
		return []string{CapPatch}
	case OpCreate, OpUpdate:
		if mount != nil {
			if ec, ok := mount.backend.(ExistenceChecker); ok {
				exists, err := ec.Exists(req)
				if err == nil {
					if exists {
						req.Operation = OpUpdate
						return []string{CapUpdate}
					}
					req.Operation = OpCreate
					return []string{CapCreate}
				}
			}
		}
		return []string{CapCreate, CapUpdate}
	}
	return nil
}

var sudoPaths = []string{"sys/audit", "sys/rotate", "sys/seal", "sys/rekey", "sys/audit-events", "sys/raw", "auth/token/accessors", "auth/token/revoke-orphan", "auth/token/create-orphan"}

func needsSudo(path string) bool {
	for _, p := range sudoPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func (c *Core) authorize(req *Request, mount *MountEntry) error {
	caps := c.requiredCaps(req, mount)
	sudo := needsSudo(req.Path)
	if !sudo && strings.HasPrefix(req.Path, "sys/") {
		for _, r := range c.sysRoute {
			if strings.HasPrefix(strings.TrimPrefix(req.Path, "sys/"), r.prefix) && r.sudo {
				sudo = true
				break
			}
		}
	}
	// LIST on "foo/" is checked against "foo/" (Vault semantics)
	path := req.Path
	if req.Operation == OpList && !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if req.ACL.Allowed(path, sudo, caps...) || (req.Operation == OpList && req.ACL.Allowed(req.Path, sudo, caps...)) {
		return nil
	}
	return errCode(403, "permission denied: %s on %q requires %s capability", req.Operation, req.Path, strings.Join(caps, " or "))
}

// CheckAccess is used by the filer/S3 layers: authorizes op on a logical path.
func (c *Core) CheckAccess(te *TokenEntry, path string, sudo bool, caps ...string) bool {
	if te == nil {
		return false
	}
	return c.ACLFor(te.Policies).Allowed(path, sudo, caps...)
}

// AuditExternal records an access made by a non-logical subsystem (fs, s3).
func (c *Core) AuditExternal(kind string, te *TokenEntry, op, path, remote string, status int, errMsg string, meta map[string]any) {
	c.audit.logExternal(kind, te, op, path, remote, status, errMsg, meta)
}

// LockState lets other subsystems run while the core is guaranteed unsealed.
func (c *Core) RLockUnsealed() error {
	c.stateMu.RLock()
	if c.barrier.Sealed() {
		c.stateMu.RUnlock()
		return ErrSealed
	}
	return nil
}

func (c *Core) RUnlock() { c.stateMu.RUnlock() }

// Stop releases resources.
func (c *Core) Stop() {
	c.Seal()
}

func (c *Core) String() string { return fmt.Sprintf("coffer-core(%s)", c.ClusterName) }
