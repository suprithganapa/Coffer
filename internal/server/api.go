package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"coffer/internal/filer"
	"coffer/internal/vault"
)

const maxRequestBody = 32 << 20

func tokenFrom(r *http.Request) string {
	for _, h := range []string{"X-Coffer-Token", "X-Vault-Token"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

func remoteAddr(r *http.Request) string { return r.RemoteAddr }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func writeErrors(w http.ResponseWriter, code int, msgs ...string) {
	writeJSON(w, code, map[string]any{"errors": msgs})
}

func errStatus(err error) int {
	var ce *vault.CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	switch {
	case errors.Is(err, filer.ErrNotFound):
		return 404
	case errors.Is(err, filer.ErrExists), errors.Is(err, filer.ErrNotEmpty), errors.Is(err, filer.ErrIsDir), errors.Is(err, filer.ErrNotDir):
		return 409
	case errors.Is(err, filer.ErrInvalidPath), errors.Is(err, filer.ErrRootReadOnly):
		return 400
	}
	return 500
}

// handleLogical serves /v1/<path> (everything except /v1/fs/).
func (s *Server) handleLogical(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	req := &vault.Request{Path: p, Token: tokenFrom(r), RemoteAddr: remoteAddr(r), Headers: r.Header, Data: map[string]any{}}
	q := r.URL.Query()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		req.Operation = vault.OpRead
		if q.Get("list") == "true" {
			req.Operation = vault.OpList
		}
		for k, v := range q {
			if k != "list" && len(v) > 0 {
				req.Data[k] = v[0]
			}
		}
	case "LIST":
		req.Operation = vault.OpList
	case http.MethodPost, http.MethodPut:
		req.Operation = vault.OpUpdate
	case http.MethodPatch:
		req.Operation = vault.OpPatch
	case http.MethodDelete:
		req.Operation = vault.OpDelete
		for k, v := range q {
			if len(v) > 0 {
				req.Data[k] = v[0]
			}
		}
	default:
		writeErrors(w, 405, "method not allowed")
		return
	}
	if r.Body != nil && (req.Operation == vault.OpUpdate || req.Operation == vault.OpPatch || req.Operation == vault.OpDelete) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
		if err != nil {
			writeErrors(w, 400, "failed to read body")
			return
		}
		if len(body) > maxRequestBody {
			writeErrors(w, 413, "request body too large")
			return
		}
		if len(strings.TrimSpace(string(body))) > 0 {
			var d map[string]any
			if err := json.Unmarshal(body, &d); err != nil {
				writeErrors(w, 400, "failed to parse JSON input: "+err.Error())
				return
			}
			for k, v := range d {
				req.Data[k] = v
			}
		}
	}
	if req.Operation == vault.OpList && !strings.HasSuffix(req.Path, "/") {
		req.Path += "/"
	}
	for _, h := range []string{"X-Coffer-Wrap-TTL", "X-Vault-Wrap-TTL"} {
		if v := r.Header.Get(h); v != "" {
			d, err := vault.ParseDuration(v)
			if err != nil || d <= 0 {
				writeErrors(w, 400, "invalid wrap TTL")
				return
			}
			req.WrapTTL = d
		}
	}
	// list paths in vault are addressed without trailing slash internally
	if req.Operation == vault.OpList {
		req.Path = strings.TrimSuffix(req.Path, "/")
	}
	resp, err := s.Core.HandleRequest(req)
	w.Header().Set("X-Request-Id", req.ID)
	if err != nil {
		writeErrors(w, errStatus(err), err.Error())
		return
	}
	if resp == nil {
		writeErrors(w, 404)
		return
	}
	if resp.Raw != nil {
		w.Header().Set("Content-Type", resp.Raw.ContentType)
		w.WriteHeader(resp.Raw.Status)
		w.Write(resp.Raw.Body)
		return
	}
	code := 200
	if resp.StatusCode != 0 {
		code = resp.StatusCode
	}
	if code == 204 || (resp.Data == nil && resp.Auth == nil && resp.WrapInfo == nil && len(resp.Warnings) == 0) {
		w.WriteHeader(204)
		return
	}
	out := map[string]any{
		"request_id": req.ID, "lease_id": "", "renewable": resp.Renewable, "lease_duration": resp.LeaseDuration,
		"data": resp.Data, "wrap_info": resp.WrapInfo, "warnings": resp.Warnings, "auth": resp.Auth,
	}
	// sys/ status endpoints are returned unwrapped (Vault compatible)
	switch p {
	case "sys/seal-status", "sys/health", "sys/init", "sys/unseal", "sys/leader":
		writeJSON(w, code, resp.Data)
		return
	}
	writeJSON(w, code, out)
}

// authFS resolves the caller's token and checks capabilities on fs/<path>.
func (s *Server) authFS(r *http.Request, aclPath string, caps ...string) (*vault.TokenEntry, error) {
	if err := s.Core.RLockUnsealed(); err != nil {
		return nil, err
	}
	defer s.Core.RUnlock()
	te, err := s.Core.LookupToken(tokenFrom(r))
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, vault.ErrPermissionDenied
	}
	if !s.Core.CheckAccess(te, aclPath, false, caps...) {
		return te, &vault.CodedError{Code: 403, Msg: "permission denied: " + strings.Join(caps, " or ") + " on " + aclPath}
	}
	return te, nil
}

func fsACL(p string) string {
	if p == "/" {
		return "fs/"
	}
	return "fs" + p
}

type fsEntryJSON struct {
	*filer.Entry
	Path      string `json:"path"`
	Encrypted bool   `json:"encrypted"`
	Bucket    string `json:"bucket,omitempty"`
}

func entryJSON(e *filer.Entry) fsEntryJSON {
	p := e.FullPath()
	if e.Name == "" {
		p = "/"
	}
	return fsEntryJSON{Entry: e, Path: p, Encrypted: e.Encrypted(), Bucket: filer.BucketOf(p)}
}

// handleFS serves the filer API under /v1/fs/.
func (s *Server) handleFS(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/v1/fs")
	p, err := filer.Clean(raw)
	if err != nil {
		writeErrors(w, 400, err.Error())
		return
	}
	q := r.URL.Query()
	var te *vault.TokenEntry
	status := 200
	var opErr error
	op := strings.ToLower(r.Method)
	defer func() {
		msg := ""
		if opErr != nil {
			msg = opErr.Error()
		}
		s.Core.AuditExternal("fs", te, op, p, remoteAddr(r), status, msg, nil)
	}()
	fail := func(err error) {
		opErr = err
		status = errStatus(err)
		writeErrors(w, status, err.Error())
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		e, err := s.Filer.Find(p)
		if err != nil {
			// authorize before revealing existence
			if te, opErr = s.authFS(r, fsACL(p), vault.CapRead, vault.CapList); opErr != nil {
				fail(opErr)
				return
			}
			fail(err)
			return
		}
		if e.IsDir {
			op = "list"
			lp := fsACL(p)
			if !strings.HasSuffix(lp, "/") {
				lp += "/"
			}
			te, err = s.authFS(r, lp, vault.CapList)
			if err != nil {
				if te, err = s.authFS(r, fsACL(p), vault.CapList); err != nil {
					fail(err)
					return
				}
			}
			limit := 1000
			if v := q.Get("limit"); v != "" {
				if n, err := atoi(v); err == nil && n > 0 {
					limit = n
				}
			}
			items, more, err := s.Filer.List(p, filer.ListOptions{StartAfter: q.Get("after"), Prefix: q.Get("prefix"), Limit: limit, ShowHidden: q.Get("hidden") == "true"})
			if err != nil {
				fail(err)
				return
			}
			out := make([]fsEntryJSON, 0, len(items))
			for _, it := range items {
				j := entryJSON(it)
				j.Chunks = nil
				out = append(out, j)
			}
			writeJSON(w, 200, map[string]any{"path": p, "entry": entryJSON(e), "entries": out, "more": more, "effective_config": s.Filer.EffectiveConfig(p)})
			return
		}
		op = "read"
		if te, err = s.authFS(r, fsACL(p), vault.CapRead); err != nil {
			fail(err)
			return
		}
		if q.Get("meta") == "true" {
			dir := e.Dir
			writeJSON(w, 200, map[string]any{"entry": entryJSON(e), "effective_config": s.Filer.EffectiveConfig(dir)})
			return
		}
		etag := e.ETag
		if etag == "" {
			etag = e.MD5
		}
		w.Header().Set("ETag", `"`+etag+`"`)
		ct := e.Mime
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if q.Get("download") == "true" {
			w.Header().Set("Content-Disposition", contentDisposition(e.Name))
		}
		http.ServeContent(w, r, "", e.Mtime, s.Filer.NewReader(e))

	case http.MethodPut:
		op = "write"
		if te, err = s.authFS(r, fsACL(p), vault.CapCreate, vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		mime := r.Header.Get("Content-Type")
		e, err := s.Filer.WriteFile(p, r.Body, filer.WriteOptions{Mime: mime, TTL: q.Get("ttl"), Owner: te.DisplayName})
		if err != nil {
			fail(err)
			return
		}
		status = 201
		writeJSON(w, 201, map[string]any{"entry": entryJSON(e)})

	case http.MethodPost:
		s.handleFSPost(w, r, p, &te, &status, &opErr, &op)

	case http.MethodDelete:
		op = "delete"
		if te, err = s.authFS(r, fsACL(p), vault.CapDelete); err != nil {
			fail(err)
			return
		}
		if bucket := filer.BucketOf(p); bucket != "" && p == filer.BucketsDir+"/"+bucket {
			err = s.Filer.DeleteBucket(bucket, q.Get("recursive") == "true")
		} else {
			err = s.Filer.Delete(p, q.Get("recursive") == "true")
		}
		if err != nil {
			fail(err)
			return
		}
		status = 204
		w.WriteHeader(204)
	default:
		fail(&vault.CodedError{Code: 405, Msg: "method not allowed"})
	}
}

func (s *Server) handleFSPost(w http.ResponseWriter, r *http.Request, p string, te **vault.TokenEntry, status *int, opErr *error, op *string) {
	q := r.URL.Query()
	fail := func(err error) {
		*opErr = err
		*status = errStatus(err)
		writeErrors(w, *status, err.Error())
	}
	var err error
	readJSON := func(v any) error {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return err
		}
		if len(body) == 0 {
			return nil
		}
		if err := json.Unmarshal(body, v); err != nil {
			return &vault.CodedError{Code: 400, Msg: "invalid JSON: " + err.Error()}
		}
		return nil
	}
	switch q.Get("op") {
	case "mkdir":
		*op = "mkdir"
		if *te, err = s.authFS(r, fsACL(p), vault.CapCreate, vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		if d, n := path.Split(p); strings.TrimSuffix(d, "/") == filer.BucketsDir && !bucketNameRe.MatchString(n) {
			fail(&vault.CodedError{Code: 400, Msg: "invalid bucket name: use 3-63 lowercase letters, digits, dots or hyphens"})
			return
		}
		e, err := s.Filer.Mkdir(p, (*te).DisplayName)
		if err != nil {
			fail(err)
			return
		}
		*status = 201
		writeJSON(w, 201, map[string]any{"entry": entryJSON(e)})
	case "rename", "copy":
		*op = q.Get("op")
		to, err := filer.Clean(q.Get("to"))
		if err != nil || q.Get("to") == "" {
			fail(&vault.CodedError{Code: 400, Msg: "missing or invalid 'to' parameter"})
			return
		}
		srcCap := vault.CapDelete
		if *op == "copy" {
			srcCap = vault.CapRead
		}
		if *te, err = s.authFS(r, fsACL(p), srcCap); err != nil {
			fail(err)
			return
		}
		if _, err = s.authFS(r, fsACL(to), vault.CapCreate, vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		var e *filer.Entry
		if *op == "rename" {
			if src, ferr := s.Filer.Find(p); ferr == nil && src.IsDir && (filer.BucketOf(p) != filer.BucketOf(to)) {
				fail(&vault.CodedError{Code: 400, Msg: "folders cannot be moved between buckets (data lives in per-bucket collections); copy files instead"})
				return
			}
			e, err = s.Filer.Rename(p, to, q.Get("overwrite") == "true")
		} else {
			e, err = s.Filer.Copy(p, to, filer.WriteOptions{Owner: (*te).DisplayName})
		}
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]any{"entry": entryJSON(e)})
	case "config":
		*op = "config"
		if *te, err = s.authFS(r, fsACL(p), vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		var cfg filer.DirConfig
		if err := readJSON(&cfg); err != nil {
			fail(err)
			return
		}
		e, err := s.Filer.SetDirConfig(p, cfg)
		if err != nil {
			if _, ok := err.(*vault.CodedError); !ok && !errors.Is(err, filer.ErrNotFound) && !errors.Is(err, filer.ErrNotDir) {
				err = &vault.CodedError{Code: 400, Msg: err.Error()}
			}
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]any{"entry": entryJSON(e), "effective_config": s.Filer.EffectiveConfig(p)})
	case "public":
		*op = "set-public"
		if *te, err = s.authFS(r, fsACL(p), vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		e, err := s.Filer.Find(p)
		if err != nil {
			fail(err)
			return
		}
		if !e.IsDir || e.Dir != filer.BucketsDir {
			fail(&vault.CodedError{Code: 400, Msg: "public access can only be set on buckets (/buckets/<name>)"})
			return
		}
		var body struct {
			Public bool `json:"public"`
		}
		if err := readJSON(&body); err != nil {
			fail(err)
			return
		}
		if e.Extended == nil {
			e.Extended = map[string]string{}
		}
		if body.Public {
			e.Extended["s3:public-read"] = "true"
		} else {
			delete(e.Extended, "s3:public-read")
		}
		if err := s.Filer.UpdateMeta(e); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, map[string]any{"entry": entryJSON(e)})
	case "share":
		*op = "share"
		if *te, err = s.authFS(r, fsACL(p), vault.CapRead); err != nil {
			fail(err)
			return
		}
		var body struct {
			TTL          string `json:"ttl"`
			MaxDownloads int    `json:"max_downloads"`
		}
		if err := readJSON(&body); err != nil {
			fail(err)
			return
		}
		sh, err := s.createShare(p, body.TTL, body.MaxDownloads, *te)
		if err != nil {
			fail(err)
			return
		}
		*status = 201
		writeJSON(w, 201, map[string]any{"share": sh})
	case "", "upload":
		*op = "upload"
		s.handleMultipartUpload(w, r, p, te, status, opErr)
	default:
		fail(&vault.CodedError{Code: 400, Msg: "unknown op " + q.Get("op") + " (mkdir, rename, copy, config, share, public, upload)"})
	}
}

// handleMultipartUpload accepts multipart/form-data with one or more files
// and stores each under directory p (browser uploads, drag & drop).
func (s *Server) handleMultipartUpload(w http.ResponseWriter, r *http.Request, dir string, te **vault.TokenEntry, status *int, opErr *error) {
	fail := func(err error) {
		*opErr = err
		*status = errStatus(err)
		writeErrors(w, *status, err.Error())
	}
	mr, err := r.MultipartReader()
	if err != nil {
		fail(&vault.CodedError{Code: 400, Msg: "expected multipart/form-data upload"})
		return
	}
	var saved []fsEntryJSON
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(&vault.CodedError{Code: 400, Msg: "malformed multipart body: " + err.Error()})
			return
		}
		name := part.FileName()
		if name == "" {
			continue
		}
		// browsers may send relative paths for folder uploads
		rel := strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/")
		target, err := filer.Clean(dir + "/" + rel)
		if err != nil || !strings.HasPrefix(target, strings.TrimSuffix(dir, "/")+"/") {
			fail(&vault.CodedError{Code: 400, Msg: "invalid file name " + name})
			return
		}
		if *te, err = s.authFS(r, fsACL(target), vault.CapCreate, vault.CapUpdate); err != nil {
			fail(err)
			return
		}
		mime := part.Header.Get("Content-Type")
		e, err := s.Filer.WriteFile(target, part, filer.WriteOptions{Mime: mime, TTL: r.URL.Query().Get("ttl"), Owner: (*te).DisplayName})
		if err != nil {
			fail(err)
			return
		}
		s.Core.AuditExternal("fs", *te, "write", target, remoteAddr(r), 201, "", map[string]any{"size": e.Size})
		saved = append(saved, entryJSON(e))
	}
	if len(saved) == 0 {
		fail(&vault.CodedError{Code: 400, Msg: "no files in upload"})
		return
	}
	*status = 201
	writeJSON(w, 201, map[string]any{"entries": saved})
}

func contentDisposition(name string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return '_'
		}
		return r
	}, name)
	return `attachment; filename="` + safe + `"; filename*=UTF-8''` + urlPathEscape(name)
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errors.New("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, errors.New("too large")
		}
	}
	return n, nil
}

var _ = time.Now

var bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
