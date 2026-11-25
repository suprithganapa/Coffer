package vault

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"coffer/internal/kvstore"
)

func newTestCore(t *testing.T, dir string) (*Core, *InitResult) {
	t.Helper()
	st, err := kvstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCore(st)
	res, err := c.Initialize(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Sealed() {
		t.Fatal("expected sealed after init")
	}
	if err := c.UnsealWithKeys(res.Keys[1:4]); err != nil {
		t.Fatal(err)
	}
	return c, res
}

func do(t *testing.T, c *Core, token, op, path string, data map[string]any) (*Response, error) {
	t.Helper()
	return c.HandleRequest(&Request{Operation: op, Path: path, Data: data, Token: token, RemoteAddr: "127.0.0.1:1234"})
}

func must(t *testing.T, r *Response, err error) *Response {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSealUnsealPersistence(t *testing.T) {
	dir := t.TempDir()
	c, res := newTestCore(t, dir)
	mustFn(t)(do(t, c, res.RootToken, OpCreate, "secret/data/app/db", map[string]any{"data": map[string]any{"password": "hunter2"}}))
	c.Seal()
	if _, err := do(t, c, res.RootToken, OpRead, "secret/data/app/db", nil); err == nil {
		t.Fatal("expected sealed error")
	}
	// wrong key resets progress
	c.Unseal(res.Keys[0], false)
	c.Unseal(res.Keys[1], false)
	if _, err := c.Unseal(strings.Repeat("ab", 33), false); err == nil {
		t.Fatal("expected bad key error")
	}
	c.store.Close()

	st, _ := kvstore.Open(dir)
	c2 := NewCore(st)
	if err := c2.UnsealWithKeys([]string{res.Keys[4], res.KeysB64[0], res.Keys[2]}); err != nil {
		t.Fatal(err)
	}
	r := mustFn(t)(do(t, c2, res.RootToken, OpRead, "secret/data/app/db", nil))
	if r.Data["data"].(map[string]any)["password"] != "hunter2" {
		t.Fatalf("bad data %v", r.Data)
	}
}

func mustFn(t *testing.T) func(*Response, error) *Response {
	return func(r *Response, err error) *Response { return must(t, r, err) }
}

func TestKVVersionsAndPolicies(t *testing.T) {
	c, res := newTestCore(t, "")
	root := res.RootToken
	m := mustFn(t)
	for i := 1; i <= 3; i++ {
		m(do(t, c, root, OpCreate, "secret/data/team/api", map[string]any{"data": map[string]any{"v": i}}))
	}
	r := m(do(t, c, root, OpRead, "secret/data/team/api", map[string]any{"version": "2"}))
	if r.Data["data"].(map[string]any)["v"] != 2 && r.Data["data"].(map[string]any)["v"] != float64(2) {
		t.Fatalf("version 2 = %v", r.Data)
	}
	m(do(t, c, root, OpDelete, "secret/data/team/api", nil))
	r, _ = do(t, c, root, OpRead, "secret/data/team/api", nil)
	if r == nil || r.StatusCode != 404 {
		t.Fatalf("expected soft-deleted 404, got %+v", r)
	}
	m(do(t, c, root, OpUpdate, "secret/undelete/team/api", map[string]any{"versions": []any{float64(3)}}))
	m(do(t, c, root, OpRead, "secret/data/team/api", nil))
	// CAS
	if _, err := do(t, c, root, OpUpdate, "secret/data/team/api", map[string]any{"data": map[string]any{"x": 1}, "options": map[string]any{"cas": float64(1)}}); err == nil {
		t.Fatal("expected cas failure")
	}
	l := m(do(t, c, root, OpList, "secret/metadata/team", nil))
	if len(l.Data["keys"].([]string)) != 1 {
		t.Fatalf("list %v", l.Data)
	}

	// policy limited token
	m(do(t, c, root, OpUpdate, "sys/policies/acl/reader", map[string]any{"policy": `
path "secret/data/team/*" { capabilities = ["read"] }
path "secret/metadata/team/*" { capabilities = ["list"] }
path "secret/data/team/locked" { capabilities = ["deny"] }
path "auth/token/create" { capabilities = ["update"] }`}))
	tr := m(do(t, c, root, OpUpdate, "auth/token/create", map[string]any{"policies": []any{"reader"}, "ttl": "1h"}))
	tok := tr.Auth.ClientToken
	m(do(t, c, tok, OpRead, "secret/data/team/api", nil))
	if _, err := do(t, c, tok, OpCreate, "secret/data/team/api", map[string]any{"data": map[string]any{"x": 1}}); err == nil {
		t.Fatal("reader must not write")
	}
	if _, err := do(t, c, tok, OpRead, "secret/data/team/locked", nil); err == nil {
		t.Fatal("deny must win")
	}
	// child cannot escalate
	if _, err := do(t, c, tok, OpUpdate, "auth/token/create", map[string]any{"policies": []any{"root"}}); err == nil {
		t.Fatal("escalation must fail")
	}
	// capabilities-self
	cr := m(do(t, c, tok, OpUpdate, "sys/capabilities-self", map[string]any{"path": "secret/data/team/x"}))
	if caps := cr.Data["capabilities"].([]string); len(caps) != 1 || caps[0] != "read" {
		t.Fatalf("caps %v", caps)
	}
	// revoke parent revokes child
	child := m(do(t, c, tok, OpUpdate, "auth/token/create", map[string]any{"policies": []any{"reader"}})).Auth.ClientToken
	m(do(t, c, root, OpUpdate, "auth/token/revoke", map[string]any{"token": tok}))
	if te, _ := c.LookupToken(child); te != nil {
		t.Fatal("child should be revoked with parent")
	}
}

func TestUserpassAppRoleWrapping(t *testing.T) {
	c, res := newTestCore(t, "")
	root := res.RootToken
	m := mustFn(t)
	m(do(t, c, root, OpUpdate, "auth/userpass/users/alice", map[string]any{"password": "correct-horse", "policies": "default"}))
	if _, err := do(t, c, "", OpUpdate, "auth/userpass/login/alice", map[string]any{"password": "nope"}); err == nil {
		t.Fatal("bad password must fail")
	}
	r := m(do(t, c, "", OpUpdate, "auth/userpass/login/alice", map[string]any{"password": "correct-horse"}))
	if r.Auth == nil || !strings.HasPrefix(r.Auth.ClientToken, "cof.") {
		t.Fatalf("login %+v", r.Auth)
	}
	m(do(t, c, r.Auth.ClientToken, OpRead, "auth/token/lookup-self", nil))

	m(do(t, c, root, OpUpdate, "sys/auth/approle", map[string]any{"type": "approle"}))
	m(do(t, c, root, OpUpdate, "auth/approle/role/ci", map[string]any{"token_policies": "default", "secret_id_num_uses": 1}))
	rid := m(do(t, c, root, OpRead, "auth/approle/role/ci/role-id", nil)).Data["role_id"].(string)
	sid := m(do(t, c, root, OpUpdate, "auth/approle/role/ci/secret-id", nil)).Data["secret_id"].(string)
	m(do(t, c, "", OpUpdate, "auth/approle/login", map[string]any{"role_id": rid, "secret_id": sid}))
	if _, err := do(t, c, "", OpUpdate, "auth/approle/login", map[string]any{"role_id": rid, "secret_id": sid}); err == nil {
		t.Fatal("single-use secret id reused")
	}

	// wrapping
	wr, err := c.HandleRequest(&Request{Operation: OpUpdate, Path: "sys/wrapping/wrap", Data: map[string]any{"db": "pw"}, Token: root, WrapTTL: time.Minute})
	if err != nil || wr.WrapInfo == nil {
		t.Fatalf("wrap %v %v", wr, err)
	}
	ur := m(do(t, c, "", OpUpdate, "sys/wrapping/unwrap", map[string]any{"token": wr.WrapInfo.Token}))
	if ur.Data["db"] != "pw" {
		t.Fatalf("unwrap %v", ur.Data)
	}
	if _, err := do(t, c, "", OpUpdate, "sys/wrapping/unwrap", map[string]any{"token": wr.WrapInfo.Token}); err == nil {
		t.Fatal("unwrap twice must fail")
	}
}

func TestTransitAndPKI(t *testing.T) {
	c, res := newTestCore(t, "")
	root := res.RootToken
	m := mustFn(t)
	m(do(t, c, root, OpCreate, "transit/keys/app", nil))
	pt := base64.StdEncoding.EncodeToString([]byte("hello world"))
	ct := m(do(t, c, root, OpUpdate, "transit/encrypt/app", map[string]any{"plaintext": pt})).Data["ciphertext"].(string)
	m(do(t, c, root, OpUpdate, "transit/keys/app/rotate", nil))
	ct2 := m(do(t, c, root, OpUpdate, "transit/rewrap/app", map[string]any{"ciphertext": ct})).Data["ciphertext"].(string)
	if !strings.HasPrefix(ct2, "coffer:v2:") {
		t.Fatalf("rewrap %s", ct2)
	}
	out := m(do(t, c, root, OpUpdate, "transit/decrypt/app", map[string]any{"ciphertext": ct2})).Data["plaintext"]
	if out != pt {
		t.Fatalf("decrypt %v", out)
	}
	m(do(t, c, root, OpCreate, "transit/keys/signer", map[string]any{"type": "ed25519"}))
	sig := m(do(t, c, root, OpUpdate, "transit/sign/signer", map[string]any{"input": pt})).Data["signature"]
	v := m(do(t, c, root, OpUpdate, "transit/verify/signer", map[string]any{"input": pt, "signature": sig})).Data["valid"]
	if v != true {
		t.Fatal("signature invalid")
	}

	m(do(t, c, root, OpUpdate, "pki/root/generate/internal", map[string]any{"common_name": "Coffer Root CA"}))
	m(do(t, c, root, OpUpdate, "pki/roles/web", map[string]any{"allowed_domains": "example.com", "allow_subdomains": true}))
	cert := m(do(t, c, root, OpUpdate, "pki/issue/web", map[string]any{"common_name": "api.example.com"}))
	if !strings.Contains(cert.Data["certificate"].(string), "BEGIN CERTIFICATE") {
		t.Fatal("no cert")
	}
	if _, err := do(t, c, root, OpUpdate, "pki/issue/web", map[string]any{"common_name": "evil.org"}); err == nil {
		t.Fatal("disallowed name issued")
	}
	m(do(t, c, root, OpUpdate, "pki/revoke", map[string]any{"serial_number": cert.Data["serial_number"]}))
	crl := m(do(t, c, "", OpRead, "pki/crl/pem", nil))
	if crl.Raw == nil || !strings.Contains(string(crl.Raw.Body), "X509 CRL") {
		t.Fatal("no crl")
	}
}

func TestPolicyMatching(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"secret/*", "secret/data/x", true},
		{"secret/+/x", "secret/data/x", true},
		{"secret/+/x", "secret/data/y", false},
		{"secret/+/team/*", "secret/data/team/a/b", true},
		{"secret/data", "secret/data/x", false},
	}
	for _, cs := range cases {
		if got := matchPattern(cs.pat, cs.path); got != cs.want {
			t.Errorf("match(%q,%q)=%v", cs.pat, cs.path, got)
		}
	}
	if !moreSpecific("secret/data/x", "secret/data/*") || !moreSpecific("secret/data/*", "secret/*") {
		t.Error("specificity")
	}
	if _, err := ParsePolicy("x", `path "a/*" { capabilities = ["read", "fly"] }`); err == nil {
		t.Error("invalid capability accepted")
	}
}
