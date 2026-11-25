package vault

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// kvBackend implements the KV secrets engine, versions 1 and 2.
//
// v2 layout in the view:
//
//	config            -> kvConfig
//	meta/<path>       -> kvMeta
//	ver/<path>/<n>    -> map[string]any (the secret data)
type kvBackend struct {
	view *View
	v2   bool
}

type kvConfig struct {
	MaxVersions        int    `json:"max_versions"`
	CASRequired        bool   `json:"cas_required"`
	DeleteVersionAfter string `json:"delete_version_after"`
}

type kvVersionMeta struct {
	CreatedTime  time.Time  `json:"created_time"`
	DeletionTime *time.Time `json:"deletion_time"`
	Destroyed    bool       `json:"destroyed"`
}

type kvMeta struct {
	CurrentVersion int                      `json:"current_version"`
	OldestVersion  int                      `json:"oldest_version"`
	MaxVersions    int                      `json:"max_versions"`
	CASRequired    bool                     `json:"cas_required"`
	CreatedTime    time.Time                `json:"created_time"`
	UpdatedTime    time.Time                `json:"updated_time"`
	CustomMetadata map[string]string        `json:"custom_metadata"`
	Versions       map[string]kvVersionMeta `json:"versions"`
}

func cleanPath(p string) string { return strings.Trim(p, "/") }

// verKey uses a NUL separator so "a" versions never collide with "a/b".
func verKey(p string, v any) string {
	switch n := v.(type) {
	case int:
		return "ver/" + p + "\x00" + strconv.Itoa(n)
	case string:
		return "ver/" + p + "\x00" + n
	}
	return ""
}

func (b *kvBackend) config() kvConfig {
	var c kvConfig
	b.view.GetJSON("config", &c)
	if c.MaxVersions <= 0 {
		c.MaxVersions = 10
	}
	return c
}

func (b *kvBackend) Exists(req *Request) (bool, error) {
	rel := req.RelPath
	if !b.v2 {
		v, err := b.view.Get("data/" + cleanPath(rel))
		return v != nil, err
	}
	for _, pre := range []string{"data/", "metadata/"} {
		if strings.HasPrefix(rel, pre) {
			v, err := b.view.Get("meta/" + cleanPath(strings.TrimPrefix(rel, pre)))
			return v != nil, err
		}
	}
	if rel == "config" {
		return true, nil
	}
	return false, nil
}

func (b *kvBackend) Handle(req *Request) (*Response, error) {
	if !b.v2 {
		return b.handleV1(req)
	}
	rel := req.RelPath
	switch {
	case rel == "config":
		return b.handleConfig(req)
	case strings.HasPrefix(rel, "data/") || rel == "data":
		return b.handleData(req, cleanPath(strings.TrimPrefix(rel, "data")))
	case strings.HasPrefix(rel, "metadata/") || rel == "metadata":
		return b.handleMetadata(req, cleanPath(strings.TrimPrefix(rel, "metadata")))
	case strings.HasPrefix(rel, "delete/"):
		return b.handleVersions(req, cleanPath(strings.TrimPrefix(rel, "delete/")), "delete")
	case strings.HasPrefix(rel, "undelete/"):
		return b.handleVersions(req, cleanPath(strings.TrimPrefix(rel, "undelete/")), "undelete")
	case strings.HasPrefix(rel, "destroy/"):
		return b.handleVersions(req, cleanPath(strings.TrimPrefix(rel, "destroy/")), "destroy")
	}
	return nil, errCode(404, "unsupported kv-v2 path %q (use data/, metadata/, delete/, undelete/, destroy/, config)", rel)
}

// ---------------- v1 ----------------

func (b *kvBackend) handleV1(req *Request) (*Response, error) {
	p := cleanPath(req.RelPath)
	switch req.Operation {
	case OpList:
		prefix := ""
		if p != "" {
			prefix = p + "/"
		}
		keys, err := b.view.List("data/" + prefix)
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	case OpRead:
		if p == "" {
			return nil, nil
		}
		var data map[string]any
		ok, err := b.view.GetJSON("data/"+p, &data)
		if err != nil || !ok {
			return nil, err
		}
		return &Response{Data: data}, nil
	case OpCreate, OpUpdate, OpPatch:
		if p == "" {
			return nil, badRequest("missing path")
		}
		if len(req.Data) == 0 {
			return nil, badRequest("no data provided")
		}
		data := req.Data
		if req.Operation == OpPatch {
			var old map[string]any
			b.view.GetJSON("data/"+p, &old)
			if old == nil {
				return nil, errCode(404, "no secret at %q to patch", p)
			}
			for k, v := range req.Data {
				if v == nil {
					delete(old, k)
				} else {
					old[k] = v
				}
			}
			data = old
		}
		return &Response{StatusCode: 204}, b.view.PutJSON("data/"+p, data)
	case OpDelete:
		return &Response{StatusCode: 204}, b.view.Delete("data/" + p)
	}
	return nil, badRequest("unsupported operation")
}

// ---------------- v2 ----------------

func (b *kvBackend) handleConfig(req *Request) (*Response, error) {
	switch req.Operation {
	case OpRead:
		c := b.config()
		return &Response{Data: toMap(c)}, nil
	case OpCreate, OpUpdate:
		c := b.config()
		if has(req.Data, "max_versions") {
			c.MaxVersions = dInt(req.Data, "max_versions", c.MaxVersions)
		}
		if has(req.Data, "cas_required") {
			c.CASRequired = dBool(req.Data, "cas_required", false)
		}
		return &Response{StatusCode: 204}, b.view.PutJSON("config", c)
	}
	return nil, badRequest("unsupported operation")
}

func (b *kvBackend) getMeta(p string) (*kvMeta, error) {
	var m kvMeta
	ok, err := b.view.GetJSON("meta/"+p, &m)
	if err != nil || !ok {
		return nil, err
	}
	if m.Versions == nil {
		m.Versions = map[string]kvVersionMeta{}
	}
	return &m, nil
}

func versionMetaJSON(n int, vm kvVersionMeta, m *kvMeta) map[string]any {
	var dt any = ""
	if vm.DeletionTime != nil {
		dt = vm.DeletionTime.Format(time.RFC3339Nano)
	}
	cm := m.CustomMetadata
	if cm == nil {
		cm = map[string]string{}
	}
	return map[string]any{"version": n, "created_time": vm.CreatedTime.Format(time.RFC3339Nano), "deletion_time": dt, "destroyed": vm.Destroyed, "custom_metadata": cm}
}

func (b *kvBackend) handleData(req *Request, p string) (*Response, error) {
	if p == "" && req.Operation != OpList {
		return nil, badRequest("missing secret path")
	}
	switch req.Operation {
	case OpList:
		return b.handleMetadata(req, p)
	case OpRead:
		m, err := b.getMeta(p)
		if err != nil || m == nil {
			return nil, err
		}
		ver := dInt(req.Data, "version", 0)
		if ver == 0 {
			ver = m.CurrentVersion
		}
		vm, ok := m.Versions[strconv.Itoa(ver)]
		if !ok {
			return nil, nil
		}
		meta := versionMetaJSON(ver, vm, m)
		if vm.Destroyed || vm.DeletionTime != nil {
			return &Response{StatusCode: 404, Data: map[string]any{"data": nil, "metadata": meta}}, nil
		}
		var data map[string]any
		if _, err := b.view.GetJSON(verKey(p, ver), &data); err != nil {
			return nil, err
		}
		return &Response{Data: map[string]any{"data": data, "metadata": meta}}, nil
	case OpCreate, OpUpdate, OpPatch:
		data, _ := req.Data["data"].(map[string]any)
		if data == nil {
			return nil, badRequest("no data provided: send {\"data\": {...}}")
		}
		cfg := b.config()
		m, err := b.getMeta(p)
		if err != nil {
			return nil, err
		}
		if m == nil {
			if req.Operation == OpPatch {
				return nil, errCode(404, "no secret at %q to patch", p)
			}
			m = &kvMeta{CreatedTime: now(), Versions: map[string]kvVersionMeta{}, OldestVersion: 1}
		}
		opts, _ := req.Data["options"].(map[string]any)
		casRequired := cfg.CASRequired || m.CASRequired
		if opts != nil && has(opts, "cas") {
			cas := dInt(opts, "cas", -1)
			if cas != m.CurrentVersion {
				return nil, badRequest("check-and-set parameter did not match the current version (current is %d)", m.CurrentVersion)
			}
		} else if casRequired {
			return nil, badRequest("check-and-set parameter required for this call")
		}
		if req.Operation == OpPatch {
			var old map[string]any
			if vm, ok := m.Versions[strconv.Itoa(m.CurrentVersion)]; ok && !vm.Destroyed && vm.DeletionTime == nil {
				b.view.GetJSON(verKey(p, m.CurrentVersion), &old)
			}
			if old == nil {
				return nil, errCode(404, "current version is deleted; cannot patch")
			}
			for k, v := range data {
				if v == nil {
					delete(old, k)
				} else {
					old[k] = v
				}
			}
			data = old
		}
		ver := m.CurrentVersion + 1
		t := now()
		if err := b.view.PutJSON(verKey(p, ver), data); err != nil {
			return nil, err
		}
		m.CurrentVersion = ver
		m.UpdatedTime = t
		m.Versions[strconv.Itoa(ver)] = kvVersionMeta{CreatedTime: t}
		max := cfg.MaxVersions
		if m.MaxVersions > 0 {
			max = m.MaxVersions
		}
		for m.CurrentVersion-m.OldestVersion+1 > max {
			b.view.Delete(verKey(p, m.OldestVersion))
			delete(m.Versions, strconv.Itoa(m.OldestVersion))
			m.OldestVersion++
		}
		if m.OldestVersion == 0 {
			m.OldestVersion = 1
		}
		if err := b.view.PutJSON("meta/"+p, m); err != nil {
			return nil, err
		}
		return &Response{Data: versionMetaJSON(ver, m.Versions[strconv.Itoa(ver)], m)}, nil
	case OpDelete:
		m, err := b.getMeta(p)
		if err != nil || m == nil {
			return &Response{StatusCode: 204}, err
		}
		key := strconv.Itoa(m.CurrentVersion)
		if vm, ok := m.Versions[key]; ok && vm.DeletionTime == nil {
			t := now()
			vm.DeletionTime = &t
			m.Versions[key] = vm
			if err := b.view.PutJSON("meta/"+p, m); err != nil {
				return nil, err
			}
		}
		return &Response{StatusCode: 204}, nil
	}
	return nil, badRequest("unsupported operation")
}

func (b *kvBackend) handleVersions(req *Request, p, action string) (*Response, error) {
	if req.Operation != OpCreate && req.Operation != OpUpdate {
		return nil, badRequest("use POST")
	}
	versions := dInts(req.Data, "versions")
	if len(versions) == 0 {
		return nil, badRequest("no versions provided")
	}
	m, err := b.getMeta(p)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errCode(404, "no secret at %q", p)
	}
	t := now()
	for _, v := range versions {
		key := strconv.Itoa(v)
		vm, ok := m.Versions[key]
		if !ok {
			continue
		}
		switch action {
		case "delete":
			if vm.DeletionTime == nil {
				vm.DeletionTime = &t
			}
		case "undelete":
			if !vm.Destroyed {
				vm.DeletionTime = nil
			}
		case "destroy":
			vm.Destroyed = true
			b.view.Delete(verKey(p, key))
		}
		m.Versions[key] = vm
	}
	return &Response{StatusCode: 204}, b.view.PutJSON("meta/"+p, m)
}

func (b *kvBackend) handleMetadata(req *Request, p string) (*Response, error) {
	switch req.Operation {
	case OpList:
		prefix := ""
		if p != "" {
			prefix = p + "/"
		}
		keys, err := b.view.List("meta/" + prefix)
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	case OpRead:
		if p == "" {
			return b.handleMetadata(&Request{Operation: OpList}, "")
		}
		m, err := b.getMeta(p)
		if err != nil || m == nil {
			return nil, err
		}
		vers := map[string]any{}
		var nums []int
		for k := range m.Versions {
			n, _ := strconv.Atoi(k)
			nums = append(nums, n)
		}
		sort.Ints(nums)
		for _, n := range nums {
			vm := m.Versions[strconv.Itoa(n)]
			j := versionMetaJSON(n, vm, m)
			delete(j, "version")
			delete(j, "custom_metadata")
			vers[strconv.Itoa(n)] = j
		}
		cm := m.CustomMetadata
		if cm == nil {
			cm = map[string]string{}
		}
		return &Response{Data: map[string]any{
			"current_version": m.CurrentVersion, "oldest_version": m.OldestVersion, "max_versions": m.MaxVersions,
			"cas_required": m.CASRequired, "created_time": m.CreatedTime.Format(time.RFC3339Nano),
			"updated_time": m.UpdatedTime.Format(time.RFC3339Nano), "custom_metadata": cm, "versions": vers,
		}}, nil
	case OpCreate, OpUpdate, OpPatch:
		if p == "" {
			return nil, badRequest("missing path")
		}
		m, err := b.getMeta(p)
		if err != nil {
			return nil, err
		}
		if m == nil {
			m = &kvMeta{CreatedTime: now(), UpdatedTime: now(), Versions: map[string]kvVersionMeta{}, OldestVersion: 1}
		}
		if has(req.Data, "max_versions") {
			m.MaxVersions = dInt(req.Data, "max_versions", 0)
		}
		if has(req.Data, "cas_required") {
			m.CASRequired = dBool(req.Data, "cas_required", false)
		}
		if cm, ok := req.Data["custom_metadata"].(map[string]any); ok {
			m.CustomMetadata = map[string]string{}
			for k, v := range cm {
				m.CustomMetadata[k] = dString(map[string]any{"v": v}, "v")
			}
		}
		return &Response{StatusCode: 204}, b.view.PutJSON("meta/"+p, m)
	case OpDelete:
		if p == "" {
			return nil, badRequest("missing path")
		}
		b.view.DeletePrefix("ver/" + p + "\x00")
		return &Response{StatusCode: 204}, b.view.Delete("meta/" + p)
	}
	return nil, badRequest("unsupported operation")
}
