package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"coffer/internal/storage"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type testNode struct {
	s      *Server
	api    string
	s3     string
	token  string
	ak, sk string
}

func startNode(t *testing.T) *testNode {
	t.Helper()
	cfg := Config{Dir: t.TempDir(), IP: "127.0.0.1", Bind: "127.0.0.1", APIPort: freePort(t), MasterPort: freePort(t), VolumePort: freePort(t), S3Port: freePort(t), Dev: true, DevRootToken: "root", VolumeSizeMB: 8, ChunkSizeMB: 1}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	n := &testNode{s: s, api: fmt.Sprintf("http://127.0.0.1:%d", cfg.APIPort), s3: fmt.Sprintf("http://127.0.0.1:%d", cfg.S3Port), token: "root"}
	// wait for the volume server to register
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.Master.Status(); st.Totals["alive_nodes"] > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return n
}

func (n *testNode) api_(t *testing.T, method, p string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, n.api+"/v1/"+p, rd)
	req.Header.Set("X-Coffer-Token", n.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ---- minimal SigV4 client for tests ----

func hm(k []byte, s string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func (n *testNode) s3req(t *testing.T, method, p string, query url.Values, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	return n.s3reqAs(t, n.ak, n.sk, method, p, query, body, hdr)
}

func enc(s string, slash bool) string { return awsEncodeTest(s, slash) }

func awsEncodeTest(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && keepSlash) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (n *testNode) s3reqAs(t *testing.T, ak, sk, method, p string, query url.Values, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	u, _ := url.Parse(n.s3)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	ph := sha256.Sum256(body)
	payload := hex.EncodeToString(ph[:])
	if v, ok := hdr["X-Amz-Content-Sha256"]; ok {
		payload = v
	}
	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		qs = append(qs, enc(k, false)+"="+enc(query.Get(k), false))
	}
	cq := strings.Join(qs, "&")
	headers := map[string]string{"host": u.Host, "x-amz-date": amzDate, "x-amz-content-sha256": payload}
	for k, v := range hdr {
		headers[strings.ToLower(k)] = v
	}
	var hk []string
	for k := range headers {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	var ch strings.Builder
	for _, k := range hk {
		ch.WriteString(k + ":" + headers[k] + "\n")
	}
	encPath := enc(p, true)
	creq := strings.Join([]string{method, encPath, cq, ch.String(), strings.Join(hk, ";"), payload}, "\n")
	scope := date + "/us-east-1/s3/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	key := hm(hm(hm(hm([]byte("AWS4"+sk), date), "us-east-1"), "s3"), "aws4_request")
	sig := hex.EncodeToString(hm(key, sts))
	full := n.s3 + encPath
	if cq != "" {
		full += "?" + cq
	}
	req, _ := http.NewRequest(method, full, bytes.NewReader(body))
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", ak, scope, strings.Join(hk, ";"), sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(t *testing.T, r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func expect(t *testing.T, r *http.Response, code int) string {
	t.Helper()
	body := readAll(t, r)
	if r.StatusCode != code {
		t.Fatalf("%s %s: status %d, want %d: %s", r.Request.Method, r.Request.URL, r.StatusCode, code, body)
	}
	return body
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestEndToEnd(t *testing.T) {
	n := startNode(t)
	code, out := n.api_(t, "POST", "sys/s3/keys", map[string]any{"policies": []string{"root"}, "description": "test"})
	if code != 200 {
		t.Fatalf("create s3 key: %d %v", code, out)
	}
	d := out["data"].(map[string]any)
	n.ak, n.sk = d["access_key"].(string), d["secret_key"].(string)

	// --- buckets & objects
	expect(t, n.s3req(t, "PUT", "/photos", nil, nil, nil), 200)
	expect(t, n.s3req(t, "PUT", "/photos", nil, nil, nil), 409)
	small := []byte("hello from s3")
	r := n.s3req(t, "PUT", "/photos/2024/trip/beach.txt", nil, small, map[string]string{"Content-Type": "text/plain", "X-Amz-Meta-Owner": "alice"})
	expect(t, r, 200)
	if r.Header.Get("ETag") == "" {
		t.Fatal("missing etag")
	}
	body := expect(t, n.s3req(t, "GET", "/photos/2024/trip/beach.txt", nil, nil, nil), 200)
	if body != string(small) {
		t.Fatalf("get body %q", body)
	}
	rr := n.s3req(t, "GET", "/photos/2024/trip/beach.txt", nil, nil, map[string]string{"Range": "bytes=6-9"})
	if b := expect(t, rr, 206); b != "from" {
		t.Fatalf("range %q", b)
	}
	if rr.Header.Get("X-Amz-Meta-Owner") != "alice" {
		t.Fatal("user metadata lost")
	}
	// bad payload hash rejected
	bad := n.s3req(t, "PUT", "/photos/bad.txt", nil, []byte("abc"), map[string]string{"X-Amz-Content-Sha256": strings.Repeat("0", 64)})
	expect(t, bad, 400)
	// wrong secret rejected
	expect(t, n.s3reqAs(t, n.ak, "wrong", "GET", "/photos/2024/trip/beach.txt", nil, nil, nil), 403)

	// big object (multi-chunk: chunk size 1MB)
	big := randBytes(3*1024*1024 + 123)
	expect(t, n.s3req(t, "PUT", "/photos/big.bin", nil, big, nil), 200)
	got := expect(t, n.s3req(t, "GET", "/photos/big.bin", nil, nil, nil), 200)
	if got != string(big) {
		t.Fatal("big object mismatch")
	}
	rg := expect(t, n.s3req(t, "GET", "/photos/big.bin", nil, nil, map[string]string{"Range": "bytes=1048570-1048590"}), 206)
	if rg != string(big[1048570:1048591]) {
		t.Fatal("cross-chunk range mismatch")
	}

	// listing v2 with delimiter
	lst := expect(t, n.s3req(t, "GET", "/photos", url.Values{"list-type": {"2"}, "delimiter": {"/"}}, nil, nil), 200)
	if !strings.Contains(lst, "<Prefix>2024/</Prefix>") || !strings.Contains(lst, "<Key>big.bin</Key>") {
		t.Fatalf("list v2: %s", lst)
	}
	lst = expect(t, n.s3req(t, "GET", "/photos", url.Values{"list-type": {"2"}, "prefix": {"2024/"}}, nil, nil), 200)
	if !strings.Contains(lst, "<Key>2024/trip/beach.txt</Key>") {
		t.Fatalf("list prefix: %s", lst)
	}
	// pagination
	lst = expect(t, n.s3req(t, "GET", "/photos", url.Values{"list-type": {"2"}, "max-keys": {"1"}}, nil, nil), 200)
	if !strings.Contains(lst, "<IsTruncated>true</IsTruncated>") || !strings.Contains(lst, "NextContinuationToken") {
		t.Fatalf("pagination: %s", lst)
	}

	// copy
	expect(t, n.s3req(t, "PUT", "/photos/copy.txt", nil, nil, map[string]string{"X-Amz-Copy-Source": "/photos/2024/trip/beach.txt"}), 200)
	if expect(t, n.s3req(t, "GET", "/photos/copy.txt", nil, nil, nil), 200) != string(small) {
		t.Fatal("copy mismatch")
	}

	// multipart
	initResp := expect(t, n.s3req(t, "POST", "/photos/video.mp4", url.Values{"uploads": {""}}, nil, map[string]string{"Content-Type": "video/mp4"}), 200)
	uid := between(initResp, "<UploadId>", "</UploadId>")
	parts := [][]byte{randBytes(1500000), randBytes(1200000), randBytes(777)}
	var etags []string
	for i, p := range parts {
		r := n.s3req(t, "PUT", "/photos/video.mp4", url.Values{"partNumber": {fmt.Sprint(i + 1)}, "uploadId": {uid}}, p, nil)
		expect(t, r, 200)
		etags = append(etags, r.Header.Get("ETag"))
	}
	lp := expect(t, n.s3req(t, "GET", "/photos/video.mp4", url.Values{"uploadId": {uid}}, nil, nil), 200)
	if strings.Count(lp, "<Part>") != 3 {
		t.Fatalf("list parts: %s", lp)
	}
	var cx strings.Builder
	cx.WriteString("<CompleteMultipartUpload>")
	for i, e := range etags {
		fmt.Fprintf(&cx, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", i+1, e)
	}
	cx.WriteString("</CompleteMultipartUpload>")
	cr := expect(t, n.s3req(t, "POST", "/photos/video.mp4", url.Values{"uploadId": {uid}}, []byte(cx.String()), nil), 200)
	if !strings.Contains(cr, "-3&#34;") && !strings.Contains(cr, "-3\"") {
		t.Fatalf("complete etag: %s", cr)
	}
	whole := append(append(append([]byte{}, parts[0]...), parts[1]...), parts[2]...)
	if expect(t, n.s3req(t, "GET", "/photos/video.mp4", nil, nil, nil), 200) != string(whole) {
		t.Fatal("multipart content mismatch")
	}
	if strings.Contains(expect(t, n.s3req(t, "GET", "/photos", url.Values{"list-type": {"2"}}, nil, nil), 200), ".uploads") {
		t.Fatal("upload staging dir leaked into listing")
	}

	// delete objects; bucket not empty
	expect(t, n.s3req(t, "DELETE", "/photos", nil, nil, nil), 409)
	del := `<Delete><Object><Key>copy.txt</Key></Object><Object><Key>2024/trip/beach.txt</Key></Object></Delete>`
	sum := md5.Sum([]byte(del))
	_ = sum
	expect(t, n.s3req(t, "POST", "/photos", url.Values{"delete": {""}}, []byte(del), nil), 200)
	expect(t, n.s3req(t, "HEAD", "/photos/copy.txt", nil, nil, nil), 404)
	lst = expect(t, n.s3req(t, "GET", "/photos", url.Values{"list-type": {"2"}, "delimiter": {"/"}}, nil, nil), 200)
	if strings.Contains(lst, "2024/") {
		t.Fatalf("empty prefix not pruned: %s", lst)
	}

	// --- policy-limited key: read-only on photos
	n.api_(t, "PUT", "sys/policies/acl/photos-ro", map[string]any{"policy": `path "fs/buckets/photos/*" { capabilities = ["read", "list"] }
path "fs/buckets/photos" { capabilities = ["read", "list"] }`})
	_, out = n.api_(t, "POST", "sys/s3/keys", map[string]any{"policies": "photos-ro"})
	d = out["data"].(map[string]any)
	roAK, roSK := d["access_key"].(string), d["secret_key"].(string)
	expect(t, n.s3reqAs(t, roAK, roSK, "GET", "/photos/big.bin", nil, nil, nil), 200)
	expect(t, n.s3reqAs(t, roAK, roSK, "PUT", "/photos/x.txt", nil, []byte("x"), nil), 403)
	expect(t, n.s3reqAs(t, roAK, roSK, "PUT", "/otherbucket", nil, nil, nil), 403)
	lb := expect(t, n.s3reqAs(t, roAK, roSK, "GET", "/", nil, nil, nil), 200)
	if !strings.Contains(lb, "<Name>photos</Name>") {
		t.Fatalf("list buckets for ro: %s", lb)
	}

	// --- encryption: bucket with transit key
	expect(t, n.s3req(t, "PUT", "/vault", nil, nil, nil), 200)
	code, out = n.api_(t, "POST", "fs/buckets/vault?op=config", map[string]any{"encryption_key": "vault-bucket"})
	if code != 200 {
		t.Fatalf("set encryption: %d %v", code, out)
	}
	secret := []byte("TOP SECRET PAYLOAD " + strings.Repeat("z", 5000))
	pr := n.s3req(t, "PUT", "/vault/plans.txt", nil, secret, nil)
	expect(t, pr, 200)
	if pr.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" {
		t.Fatal("missing SSE header")
	}
	e, err := n.s.Filer.Find("/buckets/vault/plans.txt")
	if err != nil || !e.Encrypted() {
		t.Fatalf("entry not encrypted: %v", err)
	}
	raw, err := n.s.Filer.Client.Fetch(e.Chunks[0].Fid)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("TOP SECRET")) {
		t.Fatal("plaintext found on volume server")
	}
	if expect(t, n.s3req(t, "GET", "/vault/plans.txt", nil, nil, nil), 200) != string(secret) {
		t.Fatal("decrypted mismatch")
	}
	// seal: storage access must stop, then resume after unseal
	n.s.Core.Seal()
	expect(t, n.s3req(t, "GET", "/vault/plans.txt", nil, nil, nil), 503)
	if _, err := n.s.Filer.ReadAll(e); err == nil {
		t.Fatal("decryption must fail while sealed")
	}
	if err := n.s.devInit(); err != nil {
		t.Fatal(err)
	}
	if expect(t, n.s3req(t, "GET", "/vault/plans.txt", nil, nil, nil), 200) != string(secret) {
		t.Fatal("after unseal mismatch")
	}

	// --- filer API + share links
	req, _ := http.NewRequest("PUT", n.api+"/v1/fs/docs/report.txt", strings.NewReader("quarterly numbers"))
	req.Header.Set("X-Coffer-Token", "root")
	resp, _ := http.DefaultClient.Do(req)
	expect(t, resp, 201)
	code, out = n.api_(t, "POST", "fs/docs/report.txt?op=share", map[string]any{"ttl": "1h", "max_downloads": 1})
	if code != 201 {
		t.Fatalf("share: %d %v", code, out)
	}
	surl := out["share"].(map[string]any)["url"].(string)
	sresp, _ := http.Get(surl)
	if expect(t, sresp, 200) != "quarterly numbers" {
		t.Fatal("share content")
	}
	sresp, _ = http.Get(surl)
	expect(t, sresp, 410)
	// unauthenticated filer access denied
	resp, _ = http.Get(n.api + "/v1/fs/docs/report.txt")
	expect(t, resp, 403)
	// rename + recursive delete
	code, _ = n.api_(t, "POST", "fs/docs?op=rename&to=/archive/docs", nil)
	if code != 200 {
		t.Fatalf("rename dir: %d", code)
	}
	if _, err := n.s.Filer.Find("/archive/docs/report.txt"); err != nil {
		t.Fatal("rename lost child")
	}
	code, _ = n.api_(t, "DELETE", "fs/archive", nil)
	if code != 409 {
		t.Fatalf("non-recursive delete of non-empty dir: %d", code)
	}
	code, _ = n.api_(t, "DELETE", "fs/archive?recursive=true", nil)
	if code != 204 {
		t.Fatalf("recursive delete: %d", code)
	}

	// --- audit trail covers secrets, fs and s3
	_, out = n.api_(t, "GET", "sys/audit-events?limit=500", nil)
	evs := out["data"].(map[string]any)["events"].([]any)
	kinds := map[string]bool{}
	for _, ev := range evs {
		kinds[ev.(map[string]any)["type"].(string)] = true
	}
	if !kinds["s3"] || !kinds["fs"] || !kinds["request"] {
		t.Fatalf("audit kinds %v", kinds)
	}

	// --- storage admin: vacuum reclaims space after deletes
	expect(t, n.s3req(t, "DELETE", "/photos/big.bin", nil, nil, nil), 204)
	time.Sleep(4 * time.Second) // let deletes + heartbeat land
	code, out = n.api_(t, "POST", "sys/storage/vacuum", map[string]any{"garbage_threshold": 0.1})
	if code != 200 {
		t.Fatalf("vacuum: %d %v", code, out)
	}
	code, out = n.api_(t, "GET", "sys/storage/status", nil)
	if code != 200 || out["data"].(map[string]any)["topology"] == nil {
		t.Fatalf("status: %d %v", code, out)
	}
	if expect(t, n.s3req(t, "GET", "/photos/video.mp4", nil, nil, nil), 200) != string(whole) {
		t.Fatal("data damaged by vacuum")
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return ""
	}
	return s[:j]
}

func TestReplicationAcrossVolumeServers(t *testing.T) {
	secret := &storage.ClusterAuth{Secret: []byte("test-secret")}
	m, err := storage.NewMaster(t.TempDir(), 16<<20, "001", secret)
	if err != nil {
		t.Fatal(err)
	}
	mport := freePort(t)
	msrv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", mport), Handler: m.Handler()}
	go msrv.ListenAndServe()
	defer msrv.Close()
	maddr := fmt.Sprintf("127.0.0.1:%d", mport)
	var vss []*storage.VolumeServer
	for i := 0; i < 2; i++ {
		st, _ := storage.OpenStore(t.TempDir(), 4, 16<<20)
		port := freePort(t)
		vs := storage.NewVolumeServer(st, fmt.Sprintf("127.0.0.1:%d", port), "", []string{maddr}, "dc1", "rack1", secret)
		srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: vs.Handler()}
		go srv.ListenAndServe()
		defer srv.Close()
		stop := make(chan struct{})
		defer close(stop)
		go vs.RunHeartbeat(stop)
		vss = append(vss, vs)
	}
	time.Sleep(500 * time.Millisecond)
	c := storage.NewClient(maddr, secret)
	fid, err := c.Upload([]byte("replicated!"), "r.txt", "text/plain", "", "001", "")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := storage.ParseFileID(fid)
	for i, vs := range vss {
		v := vs.Store.Get(f.VolumeID)
		if v == nil {
			t.Fatalf("volume %d missing on server %d", f.VolumeID, i)
		}
		n, err := v.Read(f.Key, f.Cookie)
		if err != nil || string(n.Data) != "replicated!" {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	if err := c.Delete(fid); err != nil {
		t.Fatal(err)
	}
	for i, vs := range vss {
		if _, err := vs.Store.Get(f.VolumeID).Read(f.Key, f.Cookie); err == nil {
			t.Fatalf("replica %d still has deleted blob", i)
		}
	}
	// unauthenticated access is refused when a cluster secret is set
	resp, _ := http.Get("http://" + vss[0].URL + "/" + fid)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestSnapshotDisasterRecovery(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, IP: "127.0.0.1", Bind: "127.0.0.1", APIPort: freePort(t), MasterPort: freePort(t), VolumePort: freePort(t), S3Port: freePort(t), Dev: true, DevRootToken: "root"}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	n := &testNode{s: s, api: fmt.Sprintf("http://127.0.0.1:%d", cfg.APIPort), token: "root"}
	n.api_(t, "POST", "secret/data/dr/db", map[string]any{"data": map[string]any{"pw": "before-disaster"}})
	if _, err := s.Filer.WriteFile("/dr/report.txt", strings.NewReader("survives"), filerWriteOpts()); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", n.api+"/v1/sys/storage/snapshot", nil)
	req.Header.Set("X-Coffer-Token", "root")
	resp, _ := http.DefaultClient.Do(req)
	snap, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.HasPrefix(snap, []byte(snapMagic)) {
		t.Fatalf("snapshot: %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	s.Shutdown(ctx)
	cancel()

	// disaster: secrets store and file index are destroyed
	os.RemoveAll(dir + "/vault")
	os.RemoveAll(dir + "/filer")
	if _, err := RestoreSnapshot(dir, bytes.NewReader(snap)); err != nil {
		t.Fatal(err)
	}
	// corrupted snapshots are rejected
	bad := append([]byte{}, snap...)
	bad[len(bad)-3] ^= 0xFF
	if _, err := RestoreSnapshot(t.TempDir(), bytes.NewReader(bad)); err == nil {
		t.Fatal("corrupt snapshot accepted")
	}

	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(); err != nil { // dev mode auto-unseals with the same key
		t.Fatal(err)
	}
	defer func() { c, cl := context.WithTimeout(context.Background(), 3*time.Second); s2.Shutdown(c); cl() }()
	time.Sleep(4 * time.Second) // volume server re-registers
	n.s = s2
	_, out := n.api_(t, "GET", "secret/data/dr/db", nil)
	if out["data"].(map[string]any)["data"].(map[string]any)["pw"] != "before-disaster" {
		t.Fatalf("secret not restored: %v", out)
	}
	e, err := s2.Filer.Find("/dr/report.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s2.Filer.ReadAll(e)
	if err != nil || string(b) != "survives" {
		t.Fatalf("file not restored: %q %v", b, err)
	}
}
