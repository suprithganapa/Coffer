package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuditEntry is one line in an audit log. Sensitive values are HMAC'd with
// a per-cluster salt so logs can be correlated without revealing secrets.
type AuditEntry struct {
	Time     time.Time      `json:"time"`
	Type     string         `json:"type"` // "request" | "fs" | "s3"
	ID       string         `json:"request_id,omitempty"`
	Auth     *AuditAuth     `json:"auth,omitempty"`
	Op       string         `json:"operation"`
	Path     string         `json:"path"`
	Remote   string         `json:"remote_address,omitempty"`
	Status   int            `json:"status"`
	Error    string         `json:"error,omitempty"`
	Request  map[string]any `json:"request_data,omitempty"`
	Response map[string]any `json:"response_data,omitempty"`
}

type AuditAuth struct {
	Accessor    string   `json:"accessor,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Policies    []string `json:"policies,omitempty"`
}

// AuditDevice config persisted in the barrier.
type AuditDevice struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Options     map[string]string `json:"options"`
}

type openDevice struct {
	cfg AuditDevice
	f   *os.File
}

// AuditBroker fans entries out to all devices plus an in-memory ring for the UI.
type AuditBroker struct {
	c       *Core
	mu      sync.Mutex
	devices map[string]*openDevice
	salt    []byte
	ring    []AuditEntry
	ringPos int
	ringLen int
}

const ringSize = 1000

func newAuditBroker(c *Core) *AuditBroker {
	return &AuditBroker{c: c, devices: map[string]*openDevice{}, ring: make([]AuditEntry, ringSize)}
}

func (a *AuditBroker) load() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.c.sysView()
	salt, err := v.Get("audit/salt")
	if err != nil {
		return err
	}
	if salt == nil {
		salt = randomBytes(32)
		if err := v.Put("audit/salt", salt); err != nil {
			return err
		}
	}
	a.salt = salt
	var devs []AuditDevice
	if _, err := v.GetJSON("audit/devices", &devs); err != nil {
		return err
	}
	for _, d := range devs {
		od, err := openAuditDevice(d)
		if err != nil {
			log.Printf("audit: cannot open device %s: %v", d.Path, err)
			continue
		}
		a.devices[d.Path] = od
	}
	return nil
}

func openAuditDevice(d AuditDevice) (*openDevice, error) {
	if d.Type != "file" {
		return nil, fmt.Errorf("unsupported audit device type %q (supported: file)", d.Type)
	}
	p := d.Options["file_path"]
	if p == "" {
		return nil, errors.New("file_path option is required")
	}
	if p == "stdout" {
		return &openDevice{cfg: d, f: os.Stdout}, nil
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &openDevice{cfg: d, f: f}, nil
}

func (a *AuditBroker) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.devices {
		if d.f != os.Stdout {
			d.f.Close()
		}
	}
	a.devices = map[string]*openDevice{}
	a.salt = nil
}

func (a *AuditBroker) persistLocked() error {
	var devs []AuditDevice
	for _, d := range a.devices {
		devs = append(devs, d.cfg)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Path < devs[j].Path })
	return a.c.sysView().PutJSON("audit/devices", devs)
}

func (a *AuditBroker) Enable(d AuditDevice) error {
	d.Path = normalizeMount(d.Path)
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.devices[d.Path]; ok {
		return badRequest("audit device %q already enabled", d.Path)
	}
	od, err := openAuditDevice(d)
	if err != nil {
		return badRequest("%v", err)
	}
	a.devices[d.Path] = od
	return a.persistLocked()
}

func (a *AuditBroker) Disable(path string) error {
	path = normalizeMount(path)
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.devices[path]
	if !ok {
		return errCode(404, "no audit device at %q", path)
	}
	if d.f != os.Stdout {
		d.f.Close()
	}
	delete(a.devices, path)
	return a.persistLocked()
}

func (a *AuditBroker) List() []AuditDevice {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditDevice
	for _, d := range a.devices {
		out = append(out, d.cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (a *AuditBroker) hmacString(s string) string {
	if a.salt == nil {
		return "hmac-sha256:redacted"
	}
	m := hmac.New(sha256.New, a.salt)
	m.Write([]byte(s))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// non-sensitive keys we keep in clear text for usefulness
var clearKeys = map[string]bool{"type": true, "policies": true, "description": true, "ttl": true, "version": true, "versions": true, "common_name": true, "max_versions": true, "path": true, "name": true, "role_name": true, "username": true, "accessor": true}

func (a *AuditBroker) redact(m map[string]any, depth int) map[string]any {
	if m == nil || depth > 4 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if clearKeys[k] {
			out[k] = v
			continue
		}
		switch vv := v.(type) {
		case string:
			out[k] = a.hmacString(vv)
		case map[string]any:
			out[k] = a.redact(vv, depth+1)
		case nil, bool, float64, int:
			out[k] = vv
		default:
			b, _ := json.Marshal(vv)
			out[k] = a.hmacString(string(b))
		}
	}
	return out
}

func (a *AuditBroker) write(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ring[a.ringPos] = e
	a.ringPos = (a.ringPos + 1) % ringSize
	if a.ringLen < ringSize {
		a.ringLen++
	}
	if len(a.devices) == 0 {
		return
	}
	line, _ := json.Marshal(e)
	line = append(line, '\n')
	for _, d := range a.devices {
		if _, err := d.f.Write(line); err != nil {
			log.Printf("audit: write to %s failed: %v", d.cfg.Path, err)
		}
	}
}

func statusOf(resp *Response, err error) int {
	if err != nil {
		var ce *CodedError
		if errors.As(err, &ce) {
			return ce.Code
		}
		return 500
	}
	if resp == nil {
		return 404
	}
	if resp.StatusCode != 0 {
		return resp.StatusCode
	}
	if resp.Data == nil && resp.Auth == nil && resp.WrapInfo == nil && resp.Raw == nil {
		return 204
	}
	return 200
}

func (a *AuditBroker) logRequest(req *Request, resp *Response, err error) {
	if req.Path == "sys/audit-events" || req.Path == "sys/seal-status" || req.Path == "sys/health" {
		return // avoid noise from UI polling
	}
	e := AuditEntry{Time: now(), Type: "request", ID: req.ID, Op: req.Operation, Path: req.Path, Remote: req.RemoteAddr, Status: statusOf(resp, err)}
	if err != nil {
		e.Error = err.Error()
	}
	if te := req.TokenEntry; te != nil {
		e.Auth = &AuditAuth{Accessor: te.Accessor, DisplayName: te.DisplayName, Policies: te.Policies}
	}
	a.mu.Lock()
	hasSalt := a.salt != nil
	a.mu.Unlock()
	if hasSalt {
		e.Request = a.redact(req.Data, 0)
		if resp != nil && resp.Data != nil {
			e.Response = a.redact(resp.Data, 0)
		}
	}
	a.write(e)
}

func (a *AuditBroker) logExternal(kind string, te *TokenEntry, op, path, remote string, status int, errMsg string, meta map[string]any) {
	e := AuditEntry{Time: now(), Type: kind, ID: uuid(), Op: op, Path: path, Remote: remote, Status: status, Error: errMsg, Request: meta}
	if te != nil {
		e.Auth = &AuditAuth{Accessor: te.Accessor, DisplayName: te.DisplayName, Policies: te.Policies}
	}
	a.write(e)
}

// Recent returns up to n most recent entries, newest first, optionally filtered.
func (a *AuditBroker) Recent(n int, filter string) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n <= 0 || n > ringSize {
		n = 200
	}
	out := make([]AuditEntry, 0, n)
	for i := 0; i < a.ringLen && len(out) < n; i++ {
		idx := (a.ringPos - 1 - i + ringSize) % ringSize
		e := a.ring[idx]
		if filter != "" && !strings.Contains(e.Path, filter) && !strings.Contains(e.Type, filter) && !strings.Contains(e.Op, filter) {
			continue
		}
		out = append(out, e)
	}
	return out
}
