// Package s3api is an Amazon S3 compatible gateway over the Coffer filer.
// Buckets are folders under /buckets; access keys and permissions come from
// the secrets core, so the same ACL policies govern S3, the filer API and
// the web UI.
package s3api

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"coffer/internal/filer"
	"coffer/internal/vault"
)

// Identity is an authenticated S3 caller.
type Identity struct {
	AccessKey string
	Secret    string
	Token     *vault.TokenEntry // synthetic token carrying the key's policies
}

// Credentials resolves access keys.
type Credentials interface {
	LookupAccessKey(accessKey string) (*Identity, error)
}

// Server is the S3 HTTP handler.
type Server struct {
	Filer  *filer.Filer
	Core   *vault.Core
	Creds  Credentials
	Region string
	Domain string // optional, enables virtual-hosted-style buckets
}

type s3Error struct {
	Status  int
	Code    string
	Message string
}

func (e *s3Error) Error() string { return e.Code + ": " + e.Message }

var (
	errAccessDenied   = &s3Error{403, "AccessDenied", "Access Denied"}
	errNoSuchBucket   = &s3Error{404, "NoSuchBucket", "The specified bucket does not exist"}
	errNoSuchKey      = &s3Error{404, "NoSuchKey", "The specified key does not exist."}
	errNoSuchUpload   = &s3Error{404, "NoSuchUpload", "The specified multipart upload does not exist."}
	errBucketExists   = &s3Error{409, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it."}
	errBucketNotEmpty = &s3Error{409, "BucketNotEmpty", "The bucket you tried to delete is not empty"}
	errInvalidBucket  = &s3Error{400, "InvalidBucketName", "The specified bucket is not valid."}
	errSealed         = &s3Error{503, "ServiceUnavailable", "Coffer is sealed; unseal it to access storage"}
	errNotImpl        = &s3Error{501, "NotImplemented", "A header or query you provided implies functionality that is not implemented"}
	errMalformedXML   = &s3Error{400, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema."}
	errInvalidPart    = &s3Error{400, "InvalidPart", "One or more of the specified parts could not be found or the ETag did not match."}
	errPreconditon    = &s3Error{412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold"}
)

func xmlResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	io.WriteString(w, xml.Header)
	xml.NewEncoder(w).Encode(v)
}

type xmlError struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var se *s3Error
	if !errors.As(err, &se) {
		switch {
		case errors.Is(err, filer.ErrNotFound):
			se = errNoSuchKey
		case errors.Is(err, vault.ErrSealed):
			se = errSealed
		default:
			se = &s3Error{500, "InternalError", err.Error()}
		}
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(se.Status)
		return
	}
	xmlResponse(w, se.Status, xmlError{Code: se.Code, Message: se.Message, Resource: r.URL.Path, RequestID: w.Header().Get("x-amz-request-id")})
}

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

func validBucket(b string) bool {
	return bucketRe.MatchString(b) && !strings.Contains(b, "..") && !strings.HasPrefix(b, "xn--")
}

func objectPath(bucket, key string) string { return filer.BucketsDir + "/" + bucket + "/" + key }

func aclPath(bucket, key string) string {
	p := "fs" + filer.BucketsDir + "/" + bucket
	if key != "" {
		p += "/" + key
	}
	return p
}

type reqCtx struct {
	id     *Identity
	bucket string
	key    string
	q      url.Values
	sig    *sigV4
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := strings.ToUpper(hex.EncodeToString(randomID(8)))
	w.Header().Set("x-amz-request-id", reqID)
	w.Header().Set("Server", "Coffer")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "ETag, x-amz-request-id, x-amz-version-id, Content-Length, Content-Range")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(200)
		return
	}
	if s.Core.Sealed() {
		s.writeError(w, r, errSealed)
		return
	}

	bucket, key := s.parsePath(r)
	ctx := &reqCtx{bucket: bucket, key: key, q: r.URL.Query()}
	sig, err := parseSigV4(r)
	if err != nil {
		s.writeError(w, r, &s3Error{400, "AuthorizationHeaderMalformed", err.Error()})
		return
	}
	if sig != nil {
		id, err := s.Creds.LookupAccessKey(sig.AccessKey)
		if err != nil || id == nil {
			s.writeError(w, r, &s3Error{403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records."})
			return
		}
		if err := sig.verify(r, id.Secret); err != nil {
			code := strings.SplitN(err.Error(), ":", 2)[0]
			msg := "The request signature we calculated does not match the signature you provided."
			if code == "RequestTimeTooSkewed" {
				msg = "The difference between the request time and the server's time is too large."
			} else if code == "AccessDenied" {
				msg = err.Error()
			}
			s.writeError(w, r, &s3Error{403, code, msg})
			return
		}
		ctx.id, ctx.sig = id, sig
	}
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	s.route(rec, r, ctx)
	var te *vault.TokenEntry
	if ctx.id != nil {
		te = ctx.id.Token
	}
	s.Core.AuditExternal("s3", te, r.Method, "/"+bucket+"/"+key, r.RemoteAddr, rec.status, "", map[string]any{"query": r.URL.RawQuery})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func (s *Server) parsePath(r *http.Request) (string, string) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if s.Domain != "" {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if strings.HasSuffix(host, "."+s.Domain) {
			return strings.TrimSuffix(host, "."+s.Domain), p
		}
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// allowed checks the caller's policies (or bucket public-read for anonymous GETs).
func (s *Server) allowed(ctx *reqCtx, p string, caps ...string) bool {
	if ctx.id == nil {
		if len(caps) == 1 && (caps[0] == vault.CapRead || caps[0] == vault.CapList) && ctx.bucket != "" {
			if e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); err == nil && e.Extended["s3:public-read"] == "true" {
				return true
			}
		}
		return false
	}
	return s.Core.CheckAccess(ctx.id.Token, p, false, caps...)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	q := ctx.q
	if ctx.bucket == "" {
		if r.Method == http.MethodGet {
			s.listBuckets(w, r, ctx)
			return
		}
		s.writeError(w, r, &s3Error{405, "MethodNotAllowed", "The specified method is not allowed against this resource."})
		return
	}
	if !validBucket(ctx.bucket) {
		s.writeError(w, r, errInvalidBucket)
		return
	}
	if ctx.key == "" {
		switch {
		case r.Method == http.MethodPut && q.Has("encryption"):
			s.putBucketEncryption(w, r, ctx)
		case r.Method == http.MethodGet && q.Has("encryption"):
			s.getBucketEncryption(w, r, ctx)
		case r.Method == http.MethodDelete && q.Has("encryption"):
			s.deleteBucketEncryption(w, r, ctx)
		case r.Method == http.MethodGet && q.Has("location"):
			if !s.bucketExists(w, r, ctx, vault.CapRead, vault.CapList) {
				return
			}
			xmlResponse(w, 200, struct {
				XMLName xml.Name `xml:"LocationConstraint"`
				NS      string   `xml:"xmlns,attr"`
				Value   string   `xml:",chardata"`
			}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Value: s.Region})
		case r.Method == http.MethodGet && q.Has("versioning"):
			if !s.bucketExists(w, r, ctx, vault.CapRead, vault.CapList) {
				return
			}
			xmlResponse(w, 200, struct {
				XMLName xml.Name `xml:"VersioningConfiguration"`
				NS      string   `xml:"xmlns,attr"`
			}{NS: "http://s3.amazonaws.com/doc/2006-03-01/"})
		case r.Method == http.MethodGet && q.Has("acl"):
			if !s.bucketExists(w, r, ctx, vault.CapRead, vault.CapList) {
				return
			}
			s.writeACL(w)
		case r.Method == http.MethodGet && (q.Has("policy") || q.Has("cors") || q.Has("lifecycle") || q.Has("website") || q.Has("replication")):
			code := map[bool]string{true: "NoSuchBucketPolicy"}[q.Has("policy")]
			if q.Has("cors") {
				code = "NoSuchCORSConfiguration"
			} else if q.Has("lifecycle") {
				code = "NoSuchLifecycleConfiguration"
			} else if q.Has("website") {
				code = "NoSuchWebsiteConfiguration"
			} else if q.Has("replication") {
				code = "ReplicationConfigurationNotFoundError"
			}
			s.writeError(w, r, &s3Error{404, code, "The configuration does not exist"})
		case r.Method == http.MethodGet && q.Has("uploads"):
			s.listMultipartUploads(w, r, ctx)
		case r.Method == http.MethodGet:
			if q.Get("list-type") == "2" {
				s.listObjects(w, r, ctx, true)
			} else {
				s.listObjects(w, r, ctx, false)
			}
		case r.Method == http.MethodHead:
			if s.bucketExists(w, r, ctx, vault.CapRead, vault.CapList) {
				w.Header().Set("x-amz-bucket-region", s.Region)
				w.WriteHeader(200)
			}
		case r.Method == http.MethodPut:
			s.createBucket(w, r, ctx)
		case r.Method == http.MethodDelete:
			s.deleteBucket(w, r, ctx)
		case r.Method == http.MethodPost && q.Has("delete"):
			s.deleteObjects(w, r, ctx)
		default:
			s.writeError(w, r, errNotImpl)
		}
		return
	}
	switch {
	case q.Has("uploadId") && r.Method == http.MethodPut:
		s.uploadPart(w, r, ctx)
	case q.Has("uploadId") && r.Method == http.MethodPost:
		s.completeMultipart(w, r, ctx)
	case q.Has("uploadId") && r.Method == http.MethodDelete:
		s.abortMultipart(w, r, ctx)
	case q.Has("uploadId") && r.Method == http.MethodGet:
		s.listParts(w, r, ctx)
	case q.Has("uploads") && r.Method == http.MethodPost:
		s.initiateMultipart(w, r, ctx)
	case q.Has("tagging"):
		s.objectTagging(w, r, ctx)
	case q.Has("acl") && r.Method == http.MethodGet:
		if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapRead) {
			s.writeError(w, r, errAccessDenied)
			return
		}
		s.writeACL(w)
	case r.Method == http.MethodPut && r.Header.Get("X-Amz-Copy-Source") != "":
		s.copyObject(w, r, ctx)
	case r.Method == http.MethodPut:
		s.putObject(w, r, ctx)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		s.getObject(w, r, ctx)
	case r.Method == http.MethodDelete:
		s.deleteObject(w, r, ctx)
	default:
		s.writeError(w, r, errNotImpl)
	}
}

func (s *Server) bucketExists(w http.ResponseWriter, r *http.Request, ctx *reqCtx, caps ...string) bool {
	if !s.allowed(ctx, aclPath(ctx.bucket, "")+"/", caps...) && !s.allowed(ctx, aclPath(ctx.bucket, ""), caps...) {
		s.writeError(w, r, errAccessDenied)
		return false
	}
	e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket)
	if err != nil || !e.IsDir {
		s.writeError(w, r, errNoSuchBucket)
		return false
	}
	return true
}

func (s *Server) writeACL(w http.ResponseWriter) {
	type grantee struct {
		XSI  string `xml:"xmlns:xsi,attr"`
		Type string `xml:"xsi:type,attr"`
		ID   string `xml:"ID"`
	}
	type grant struct {
		Grantee    grantee `xml:"Grantee"`
		Permission string  `xml:"Permission"`
	}
	xmlResponse(w, 200, struct {
		XMLName xml.Name `xml:"AccessControlPolicy"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Grants []grant `xml:"AccessControlList>Grant"`
	}{Grants: []grant{{Grantee: grantee{XSI: "http://www.w3.org/2001/XMLSchema-instance", Type: "CanonicalUser", ID: "coffer"}, Permission: "FULL_CONTROL"}}})
}

// ---------------- buckets ----------------

type bucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if ctx.id == nil {
		s.writeError(w, r, errAccessDenied)
		return
	}
	entries, _, err := s.Filer.List(filer.BucketsDir, filer.ListOptions{Limit: 10000})
	if err != nil && !errors.Is(err, filer.ErrNotFound) {
		s.writeError(w, r, err)
		return
	}
	acl := s.Core.ACLFor(ctx.id.Token.Policies)
	var out []bucketXML
	for _, e := range entries {
		if !e.IsDir {
			continue
		}
		if !acl.AnyUnder(aclPath(e.Name, "")) {
			continue
		}
		out = append(out, bucketXML{Name: e.Name, CreationDate: e.Crtime.Format(time.RFC3339)})
	}
	xmlResponse(w, 200, struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		NS      string   `xml:"xmlns,attr"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets []bucketXML `xml:"Buckets>Bucket"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Buckets: out})
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ""), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	if e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); err == nil && e.IsDir {
		s.writeError(w, r, errBucketExists)
		return
	}
	owner := ""
	if ctx.id != nil {
		owner = ctx.id.Token.DisplayName
	}
	if _, err := s.Filer.Mkdir(filer.BucketsDir+"/"+ctx.bucket, owner); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/"+ctx.bucket)
	w.WriteHeader(200)
}

func (s *Server) deleteBucket(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ""), vault.CapDelete) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	err := s.Filer.DeleteBucket(ctx.bucket, false)
	switch {
	case errors.Is(err, filer.ErrNotFound):
		s.writeError(w, r, errNoSuchBucket)
	case errors.Is(err, filer.ErrNotEmpty):
		s.writeError(w, r, errBucketNotEmpty)
	case err != nil:
		s.writeError(w, r, err)
	default:
		w.WriteHeader(204)
	}
}

type sseConfig struct {
	XMLName xml.Name `xml:"ServerSideEncryptionConfiguration"`
	NS      string   `xml:"xmlns,attr,omitempty"`
	Rules   []struct {
		Apply struct {
			SSEAlgorithm   string `xml:"SSEAlgorithm"`
			KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
	} `xml:"Rule"`
}

func (s *Server) putBucketEncryption(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ""), vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	var cfg sseConfig
	if err := xml.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cfg); err != nil || len(cfg.Rules) == 0 {
		s.writeError(w, r, errMalformedXML)
		return
	}
	key := cfg.Rules[0].Apply.KMSMasterKeyID
	if key == "" {
		key = "s3-" + strings.ReplaceAll(ctx.bucket, ".", "-")
	}
	e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket)
	if err != nil {
		s.writeError(w, r, errNoSuchBucket)
		return
	}
	dc := filer.DirConfig{}
	if e.Config != nil {
		dc = *e.Config
	}
	dc.EncryptionKey = key
	if _, err := s.Filer.SetDirConfig(e.FullPath(), dc); err != nil {
		s.writeError(w, r, &s3Error{400, "InvalidArgument", err.Error()})
		return
	}
	w.WriteHeader(200)
}

func (s *Server) getBucketEncryption(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.bucketExists(w, r, ctx, vault.CapRead, vault.CapList) {
		return
	}
	e, _ := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket)
	if e.Config == nil || e.Config.EncryptionKey == "" || e.Config.EncryptionKey == "-" {
		s.writeError(w, r, &s3Error{404, "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found"})
		return
	}
	var cfg sseConfig
	cfg.NS = "http://s3.amazonaws.com/doc/2006-03-01/"
	cfg.Rules = make([]struct {
		Apply struct {
			SSEAlgorithm   string `xml:"SSEAlgorithm"`
			KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
	}, 1)
	cfg.Rules[0].Apply.SSEAlgorithm = "aws:kms"
	cfg.Rules[0].Apply.KMSMasterKeyID = e.Config.EncryptionKey
	xmlResponse(w, 200, cfg)
}

func (s *Server) deleteBucketEncryption(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ""), vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket)
	if err != nil {
		s.writeError(w, r, errNoSuchBucket)
		return
	}
	if e.Config != nil {
		dc := *e.Config
		dc.EncryptionKey = ""
		s.Filer.SetDirConfig(e.FullPath(), dc)
	}
	w.WriteHeader(204)
}

// ---------------- listing ----------------

type objectXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type prefixXML struct {
	Prefix string `xml:"Prefix"`
}

type listItem struct {
	key   string
	entry *filer.Entry
	isPfx bool
}

// collect gathers keys under prefix, honoring delimiter "/".
func (s *Server) collect(bucket, prefix, delimiter string) ([]listItem, error) {
	root := filer.BucketsDir + "/" + bucket
	dirPart := ""
	namePrefix := prefix
	if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
		dirPart, namePrefix = prefix[:i], prefix[i+1:]
	}
	start := root
	if dirPart != "" {
		start = root + "/" + dirPart
	}
	var items []listItem
	keyOf := func(e *filer.Entry) string {
		return strings.TrimPrefix(e.FullPath(), root+"/")
	}
	entries, _, err := s.Filer.List(start, filer.ListOptions{Prefix: namePrefix, Limit: 1 << 30})
	if err != nil {
		if errors.Is(err, filer.ErrNotFound) || errors.Is(err, filer.ErrNotDir) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		k := keyOf(e)
		if e.IsDir {
			if delimiter == "/" {
				items = append(items, listItem{key: k + "/", isPfx: true})
				continue
			}
			sub := 0
			s.Filer.Walk(e.FullPath(), func(c *filer.Entry) {
				if !c.IsDir && !c.Expired() {
					items = append(items, listItem{key: keyOf(c), entry: c})
					sub++
				}
			})
			if sub == 0 {
				items = append(items, listItem{key: k + "/", entry: e})
			}
			continue
		}
		items = append(items, listItem{key: k, entry: e})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	return items, nil
}

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request, ctx *reqCtx, v2 bool) {
	if !s.bucketExists(w, r, ctx, vault.CapList, vault.CapRead) {
		return
	}
	q := ctx.q
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	if delim != "" && delim != "/" {
		s.writeError(w, r, &s3Error{400, "InvalidArgument", "only '/' is supported as a delimiter"})
		return
	}
	maxKeys := 1000
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			s.writeError(w, r, &s3Error{400, "InvalidArgument", "invalid max-keys"})
			return
		}
		if n < maxKeys {
			maxKeys = n
		}
	}
	marker := q.Get("marker")
	if v2 {
		marker = q.Get("start-after")
		if t := q.Get("continuation-token"); t != "" {
			b, err := base64.StdEncoding.DecodeString(t)
			if err != nil {
				s.writeError(w, r, &s3Error{400, "InvalidArgument", "invalid continuation token"})
				return
			}
			marker = string(b)
		}
	}
	items, err := s.collect(ctx.bucket, prefix, delim)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	encode := q.Get("encoding-type") == "url"
	enc := func(k string) string {
		if encode {
			return strings.ReplaceAll(url.QueryEscape(k), "%2F", "/")
		}
		return k
	}
	var contents []objectXML
	var prefixes []prefixXML
	truncated := false
	last := ""
	for _, it := range items {
		if marker != "" && it.key <= marker {
			continue
		}
		if len(contents)+len(prefixes) >= maxKeys {
			truncated = true
			break
		}
		last = it.key
		if it.isPfx {
			prefixes = append(prefixes, prefixXML{enc(it.key)})
			continue
		}
		etag := it.entry.ETag
		if etag == "" {
			etag = it.entry.MD5
		}
		contents = append(contents, objectXML{Key: enc(it.key), LastModified: it.entry.Mtime.UTC().Format("2006-01-02T15:04:05.000Z"), ETag: `"` + etag + `"`, Size: it.entry.Size, StorageClass: "STANDARD"})
	}
	type result struct {
		XMLName               xml.Name    `xml:"ListBucketResult"`
		NS                    string      `xml:"xmlns,attr"`
		Name                  string      `xml:"Name"`
		Prefix                string      `xml:"Prefix"`
		Marker                *string     `xml:"Marker,omitempty"`
		NextMarker            string      `xml:"NextMarker,omitempty"`
		StartAfter            string      `xml:"StartAfter,omitempty"`
		ContinuationToken     string      `xml:"ContinuationToken,omitempty"`
		NextContinuationToken string      `xml:"NextContinuationToken,omitempty"`
		KeyCount              *int        `xml:"KeyCount,omitempty"`
		MaxKeys               int         `xml:"MaxKeys"`
		Delimiter             string      `xml:"Delimiter,omitempty"`
		EncodingType          string      `xml:"EncodingType,omitempty"`
		IsTruncated           bool        `xml:"IsTruncated"`
		Contents              []objectXML `xml:"Contents"`
		CommonPrefixes        []prefixXML `xml:"CommonPrefixes"`
	}
	res := result{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Name: ctx.bucket, Prefix: enc(prefix), MaxKeys: maxKeys, Delimiter: delim, IsTruncated: truncated, Contents: contents, CommonPrefixes: prefixes}
	if encode {
		res.EncodingType = "url"
	}
	if v2 {
		kc := len(contents) + len(prefixes)
		res.KeyCount = &kc
		res.StartAfter = q.Get("start-after")
		res.ContinuationToken = q.Get("continuation-token")
		if truncated {
			res.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(last))
		}
	} else {
		m := q.Get("marker")
		res.Marker = &m
		if truncated {
			res.NextMarker = last
		}
	}
	xmlResponse(w, 200, res)
}

// ---------------- objects ----------------

var storedHeaders = []string{"Content-Type", "Content-Disposition", "Content-Encoding", "Content-Language", "Cache-Control", "Expires", "Content-Type"}

func extendedFromHeaders(h http.Header) map[string]string {
	ext := map[string]string{}
	for k, vs := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") && len(vs) > 0 {
			ext[lk] = vs[0]
		}
	}
	for _, k := range storedHeaders {
		if v := h.Get(k); v != "" && k != "Content-Type" {
			ext[strings.ToLower(k)] = v
		}
	}
	if t := h.Get("X-Amz-Tagging"); t != "" {
		ext["s3:tagging"] = t
	}
	return ext
}

func randomID(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(cryptoRand, b); err != nil {
		panic(err)
	}
	return b
}

// bodyReader decodes aws-chunked bodies and verifies payload hashes.
type verifiedBody struct {
	io.Reader
	sha     hash.Hash
	md5     hash.Hash
	wantSHA string
	wantMD5 string
}

func (s *Server) body(r *http.Request, ctx *reqCtx) (*verifiedBody, error) {
	vb := &verifiedBody{Reader: r.Body}
	ph := ""
	if ctx.sig != nil && !ctx.sig.Presigned {
		ph = r.Header.Get("X-Amz-Content-Sha256")
	}
	switch ph {
	case streamingSigned, streamingSignedTrail:
		vb.Reader = newChunkedReader(r.Body, ctx.sig, ctx.id.Secret, true)
	case streamingTrail:
		vb.Reader = newChunkedReader(r.Body, ctx.sig, "", false)
	case "", unsignedPayload:
		if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
			vb.Reader = newChunkedReader(r.Body, ctx.sig, "", false)
		}
	default:
		if len(ph) != 64 {
			return nil, &s3Error{400, "InvalidArgument", "invalid x-amz-content-sha256"}
		}
		vb.sha = sha256.New()
		vb.wantSHA = ph
	}
	if m := r.Header.Get("Content-MD5"); m != "" {
		raw, err := base64.StdEncoding.DecodeString(m)
		if err != nil || len(raw) != 16 {
			return nil, &s3Error{400, "InvalidDigest", "The Content-MD5 you specified is not valid."}
		}
		vb.md5 = md5.New()
		vb.wantMD5 = hex.EncodeToString(raw)
	}
	var ws []io.Writer
	if vb.sha != nil {
		ws = append(ws, vb.sha)
	}
	if vb.md5 != nil {
		ws = append(ws, vb.md5)
	}
	if len(ws) > 0 {
		vb.Reader = io.TeeReader(vb.Reader, io.MultiWriter(ws...))
	}
	return vb, nil
}

func (vb *verifiedBody) check() error {
	if vb.sha != nil && hex.EncodeToString(vb.sha.Sum(nil)) != vb.wantSHA {
		return &s3Error{400, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed."}
	}
	if vb.md5 != nil && hex.EncodeToString(vb.md5.Sum(nil)) != vb.wantMD5 {
		return &s3Error{400, "BadDigest", "The Content-MD5 you specified did not match what we received."}
	}
	return nil
}

func (s *Server) encryptionFor(r *http.Request, dir string) (filer.DirConfig, error) {
	cfg := s.Filer.EffectiveConfig(dir)
	switch r.Header.Get("X-Amz-Server-Side-Encryption") {
	case "":
	case "aws:kms", "AES256":
		if k := r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"); k != "" {
			cfg.EncryptionKey = k
		} else if cfg.EncryptionKey == "" {
			cfg.EncryptionKey = "s3-default"
		}
		if err := s.Filer.Keys.EnsureTransitKey(cfg.EncryptionKey); err != nil {
			return cfg, &s3Error{400, "KMS.NotFoundException", err.Error()}
		}
	default:
		return cfg, &s3Error{400, "InvalidArgument", "unsupported server side encryption"}
	}
	return cfg, nil
}

func ownerOf(ctx *reqCtx) string {
	if ctx.id != nil {
		return ctx.id.Token.DisplayName
	}
	return "anonymous"
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	p := objectPath(ctx.bucket, ctx.key)
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	if e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); err != nil || !e.IsDir {
		s.writeError(w, r, errNoSuchBucket)
		return
	}
	if strings.HasSuffix(ctx.key, "/") {
		// directory marker
		if _, err := s.Filer.Mkdir(p, ownerOf(ctx)); err != nil {
			s.writeError(w, r, err)
			return
		}
		w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
		w.WriteHeader(200)
		return
	}
	if err := checkWritePreconditions(s, r, p); err != nil {
		s.writeError(w, r, err)
		return
	}
	vb, err := s.body(r, ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	dir, name := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	cfg, err := s.encryptionFor(r, dir)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	mime := r.Header.Get("Content-Type")
	chunks, size, sum, err := s.Filer.UploadChunks(vb, dir, name, mime, cfg)
	if err != nil {
		s.writeError(w, r, mapUploadErr(err))
		return
	}
	if err := vb.check(); err != nil {
		s.Filer.DeleteChunksAsync(chunks)
		s.writeError(w, r, err)
		return
	}
	t := time.Now().UTC()
	e := &filer.Entry{Dir: dir, Name: name, Mode: 0o644, Mtime: t, Crtime: t, Mime: mime, Size: size, MD5: sum, ETag: sum, Chunks: chunks, TTL: cfg.TTL, Extended: extendedFromHeaders(r.Header), Owner: ownerOf(ctx)}
	if err := s.Filer.Save(e); err != nil {
		s.Filer.DeleteChunksAsync(chunks)
		s.writeError(w, r, mapUploadErr(err))
		return
	}
	setSSEHeaders(w, e)
	w.Header().Set("ETag", `"`+sum+`"`)
	w.WriteHeader(200)
}

func mapUploadErr(err error) error {
	switch {
	case errors.Is(err, filer.ErrIsDir), errors.Is(err, filer.ErrNotDir):
		return &s3Error{409, "InvalidRequest", "object key conflicts with an existing folder or object: " + err.Error()}
	case errors.Is(err, errChunkSig):
		return &s3Error{403, "SignatureDoesNotMatch", "chunk signature mismatch"}
	}
	var se *s3Error
	if errors.As(err, &se) {
		return se
	}
	return err
}

func checkWritePreconditions(s *Server, r *http.Request, p string) error {
	inm := r.Header.Get("If-None-Match")
	im := r.Header.Get("If-Match")
	if inm == "" && im == "" {
		return nil
	}
	e, err := s.Filer.Find(p)
	exists := err == nil && !e.IsDir
	if inm == "*" && exists {
		return errPreconditon
	}
	if im != "" && (!exists || strings.Trim(im, `"`) != e.ETag) {
		return errPreconditon
	}
	return nil
}

func setSSEHeaders(w http.ResponseWriter, e *filer.Entry) {
	if e.Encrypted() {
		w.Header().Set("x-amz-server-side-encryption", "aws:kms")
		for _, c := range e.Chunks {
			if c.KeyName != "" {
				w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", c.KeyName)
				break
			}
		}
	}
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapRead) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	e, err := s.Filer.Find(objectPath(ctx.bucket, ctx.key))
	if err != nil {
		if _, berr := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); berr != nil {
			s.writeError(w, r, errNoSuchBucket)
			return
		}
		s.writeError(w, r, errNoSuchKey)
		return
	}
	if e.IsDir {
		if strings.HasSuffix(ctx.key, "/") {
			w.Header().Set("Content-Length", "0")
			w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
			w.WriteHeader(200)
			return
		}
		s.writeError(w, r, errNoSuchKey)
		return
	}
	etag := e.ETag
	if etag == "" {
		etag = e.MD5
	}
	h := w.Header()
	h.Set("ETag", `"`+etag+`"`)
	h.Set("Accept-Ranges", "bytes")
	ct := e.Mime
	if ct == "" {
		ct = "binary/octet-stream"
	}
	h.Set("Content-Type", ct)
	for k, v := range e.Extended {
		if strings.HasPrefix(k, "s3:") {
			continue
		}
		h.Set(k, v)
	}
	q := ctx.q
	for _, o := range []string{"response-content-type", "response-content-disposition", "response-cache-control", "response-content-encoding", "response-content-language", "response-expires"} {
		if v := q.Get(o); v != "" {
			h.Set(strings.TrimPrefix(o, "response-"), v)
		}
	}
	setSSEHeaders(w, e)
	if t := e.Extended["s3:tagging"]; t != "" {
		vals, _ := url.ParseQuery(t)
		h.Set("x-amz-tagging-count", strconv.Itoa(len(vals)))
	}
	rd := s.Filer.NewReader(e)
	http.ServeContent(w, r, "", e.Mtime, &errLogReader{rd: rd, path: e.FullPath()})
}

type errLogReader struct {
	rd   io.ReadSeeker
	path string
}

func (e *errLogReader) Read(p []byte) (int, error) {
	n, err := e.rd.Read(p)
	if err != nil && err != io.EOF {
		log.Printf("s3: read %s: %v", e.path, err)
	}
	return n, err
}

func (e *errLogReader) Seek(o int64, w int) (int64, error) { return e.rd.Seek(o, w) }

func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapDelete) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	if _, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); err != nil {
		s.writeError(w, r, errNoSuchBucket)
		return
	}
	p := objectPath(ctx.bucket, strings.TrimSuffix(ctx.key, "/"))
	err := s.Filer.Delete(p, false)
	if err != nil && !errors.Is(err, filer.ErrNotFound) && !errors.Is(err, filer.ErrNotEmpty) {
		s.writeError(w, r, err)
		return
	}
	s.pruneEmptyParents(ctx.bucket, p)
	w.WriteHeader(204)
}

// pruneEmptyParents removes implicit folders left empty by deletes so S3
// listings don't show phantom prefixes.
func (s *Server) pruneEmptyParents(bucket, p string) {
	root := filer.BucketsDir + "/" + bucket
	dir := path.Dir(p)
	for dir != root && strings.HasPrefix(dir, root+"/") {
		e, err := s.Filer.Find(dir)
		if err != nil || !e.IsDir || e.Config != nil {
			return
		}
		if s.Filer.Delete(dir, false) != nil {
			return
		}
		dir = path.Dir(dir)
	}
}

func (s *Server) deleteObjects(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.bucketExists(w, r, ctx, vault.CapList, vault.CapRead, vault.CapDelete) {
		return
	}
	var req struct {
		Quiet   bool `xml:"Quiet"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if err := xml.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		s.writeError(w, r, errMalformedXML)
		return
	}
	if len(req.Objects) > 1000 {
		s.writeError(w, r, &s3Error{400, "MalformedXML", "too many objects (max 1000)"})
		return
	}
	type deleted struct {
		Key string `xml:"Key"`
	}
	type delErr struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	var oks []deleted
	var errs []delErr
	for _, o := range req.Objects {
		if !s.allowed(ctx, aclPath(ctx.bucket, o.Key), vault.CapDelete) {
			errs = append(errs, delErr{o.Key, "AccessDenied", "Access Denied"})
			continue
		}
		p := objectPath(ctx.bucket, strings.TrimSuffix(o.Key, "/"))
		if err := s.Filer.Delete(p, false); err != nil && !errors.Is(err, filer.ErrNotFound) {
			errs = append(errs, delErr{o.Key, "InternalError", err.Error()})
			continue
		}
		s.pruneEmptyParents(ctx.bucket, p)
		if !req.Quiet {
			oks = append(oks, deleted{o.Key})
		}
	}
	xmlResponse(w, 200, struct {
		XMLName xml.Name  `xml:"DeleteResult"`
		NS      string    `xml:"xmlns,attr"`
		Deleted []deleted `xml:"Deleted"`
		Errors  []delErr  `xml:"Error"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Deleted: oks, Errors: errs})
}

func parseCopySource(h string) (string, string, error) {
	src, err := url.PathUnescape(strings.SplitN(h, "?", 2)[0])
	if err != nil {
		return "", "", err
	}
	src = strings.TrimPrefix(src, "/")
	i := strings.IndexByte(src, '/')
	if i <= 0 || i == len(src)-1 {
		return "", "", errors.New("invalid copy source")
	}
	return src[:i], src[i+1:], nil
}

func (s *Server) copyObject(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	sb, sk, err := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		s.writeError(w, r, &s3Error{400, "InvalidArgument", "Copy Source must mention the source bucket and key: sourcebucket/sourcekey"})
		return
	}
	if !s.allowed(ctx, aclPath(sb, sk), vault.CapRead) || !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	src, err := s.Filer.Find(objectPath(sb, sk))
	if err != nil || src.IsDir {
		s.writeError(w, r, errNoSuchKey)
		return
	}
	if v := r.Header.Get("X-Amz-Copy-Source-If-Match"); v != "" && strings.Trim(v, `"`) != src.ETag {
		s.writeError(w, r, errPreconditon)
		return
	}
	if v := r.Header.Get("X-Amz-Copy-Source-If-None-Match"); v != "" && strings.Trim(v, `"`) == src.ETag {
		s.writeError(w, r, errPreconditon)
		return
	}
	dst := objectPath(ctx.bucket, ctx.key)
	replace := r.Header.Get("X-Amz-Metadata-Directive") == "REPLACE"
	ext, mime := src.Extended, src.Mime
	if replace {
		ext, mime = extendedFromHeaders(r.Header), r.Header.Get("Content-Type")
	}
	var out *filer.Entry
	if dst == src.FullPath() {
		if !replace {
			s.writeError(w, r, &s3Error{400, "InvalidRequest", "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."})
			return
		}
		src.Extended, src.Mime, src.Mtime = ext, mime, time.Now().UTC()
		if err := s.Filer.UpdateMeta(src); err != nil {
			s.writeError(w, r, err)
			return
		}
		out = src
	} else {
		dir, name := path.Split(dst)
		dir = strings.TrimSuffix(dir, "/")
		cfg, err := s.encryptionFor(r, dir)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		chunks, size, sum, err := s.Filer.UploadChunks(s.Filer.NewReader(src), dir, name, mime, cfg)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		t := time.Now().UTC()
		out = &filer.Entry{Dir: dir, Name: name, Mode: 0o644, Mtime: t, Crtime: t, Mime: mime, Size: size, MD5: sum, ETag: src.ETag, Chunks: chunks, TTL: cfg.TTL, Extended: ext, Owner: ownerOf(ctx)}
		if strings.Contains(src.ETag, "-") {
			out.ETag = sum
		}
		if err := s.Filer.Save(out); err != nil {
			s.Filer.DeleteChunksAsync(chunks)
			s.writeError(w, r, mapUploadErr(err))
			return
		}
	}
	setSSEHeaders(w, out)
	xmlResponse(w, 200, struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		LastModified string   `xml:"LastModified"`
		ETag         string   `xml:"ETag"`
	}{LastModified: out.Mtime.Format("2006-01-02T15:04:05.000Z"), ETag: `"` + out.ETag + `"`})
}

func (s *Server) objectTagging(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	p := objectPath(ctx.bucket, ctx.key)
	type tag struct {
		Key   string `xml:"Key"`
		Value string `xml:"Value"`
	}
	type tagging struct {
		XMLName xml.Name `xml:"Tagging"`
		Tags    []tag    `xml:"TagSet>Tag"`
	}
	cap := vault.CapRead
	if r.Method != http.MethodGet {
		cap = vault.CapUpdate
	}
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), cap) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	e, err := s.Filer.Find(p)
	if err != nil || e.IsDir {
		s.writeError(w, r, errNoSuchKey)
		return
	}
	switch r.Method {
	case http.MethodGet:
		vals, _ := url.ParseQuery(e.Extended["s3:tagging"])
		var t tagging
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Tags = append(t.Tags, tag{k, vals.Get(k)})
		}
		xmlResponse(w, 200, t)
	case http.MethodPut:
		var t tagging
		if err := xml.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&t); err != nil {
			s.writeError(w, r, errMalformedXML)
			return
		}
		if len(t.Tags) > 10 {
			s.writeError(w, r, &s3Error{400, "BadRequest", "Object tags cannot be greater than 10"})
			return
		}
		v := url.Values{}
		for _, tg := range t.Tags {
			v.Set(tg.Key, tg.Value)
		}
		if e.Extended == nil {
			e.Extended = map[string]string{}
		}
		e.Extended["s3:tagging"] = v.Encode()
		if err := s.Filer.UpdateMeta(e); err != nil {
			s.writeError(w, r, err)
			return
		}
		w.WriteHeader(200)
	case http.MethodDelete:
		delete(e.Extended, "s3:tagging")
		s.Filer.UpdateMeta(e)
		w.WriteHeader(204)
	default:
		s.writeError(w, r, errNotImpl)
	}
}

// ---------------- multipart ----------------

func uploadDir(bucket, id string) string {
	return filer.BucketsDir + "/" + bucket + "/.uploads/" + id
}

func (s *Server) initiateMultipart(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	if e, err := s.Filer.Find(filer.BucketsDir + "/" + ctx.bucket); err != nil || !e.IsDir {
		s.writeError(w, r, errNoSuchBucket)
		return
	}
	dir := path.Dir(objectPath(ctx.bucket, ctx.key))
	cfg, err := s.encryptionFor(r, dir)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	id := hex.EncodeToString(randomID(16))
	d, err := s.Filer.Mkdir(uploadDir(ctx.bucket, id), ownerOf(ctx))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	ext := extendedFromHeaders(r.Header)
	ext["s3:key"] = ctx.key
	ext["s3:mime"] = r.Header.Get("Content-Type")
	ext["s3:enc-key"] = cfg.EncryptionKey
	d.Extended = ext
	if err := s.Filer.UpdateMeta(d); err != nil {
		s.writeError(w, r, err)
		return
	}
	xmlResponse(w, 200, struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		NS       string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: ctx.bucket, Key: ctx.key, UploadID: id})
}

func (s *Server) findUpload(ctx *reqCtx) (*filer.Entry, error) {
	id := ctx.q.Get("uploadId")
	if id == "" || strings.ContainsAny(id, "/.") {
		return nil, errNoSuchUpload
	}
	d, err := s.Filer.Find(uploadDir(ctx.bucket, id))
	if err != nil || !d.IsDir || d.Extended["s3:key"] != ctx.key {
		return nil, errNoSuchUpload
	}
	return d, nil
}

func partName(n int) string { return fmt.Sprintf("%05d.part", n) }

func (s *Server) uploadPart(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	up, err := s.findUpload(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := strconv.Atoi(ctx.q.Get("partNumber"))
	if err != nil || n < 1 || n > 10000 {
		s.writeError(w, r, &s3Error{400, "InvalidArgument", "Part number must be an integer between 1 and 10000, inclusive"})
		return
	}
	cfg := filer.DirConfig{EncryptionKey: up.Extended["s3:enc-key"]}
	cfg.Replication = s.Filer.EffectiveConfig(path.Dir(objectPath(ctx.bucket, ctx.key))).Replication
	var src io.Reader
	var vb *verifiedBody
	if cs := r.Header.Get("X-Amz-Copy-Source"); cs != "" {
		sb, sk, err := parseCopySource(cs)
		if err != nil {
			s.writeError(w, r, &s3Error{400, "InvalidArgument", "invalid copy source"})
			return
		}
		if !s.allowed(ctx, aclPath(sb, sk), vault.CapRead) {
			s.writeError(w, r, errAccessDenied)
			return
		}
		se, err := s.Filer.Find(objectPath(sb, sk))
		if err != nil || se.IsDir {
			s.writeError(w, r, errNoSuchKey)
			return
		}
		rd := s.Filer.NewReader(se)
		var start, end int64 = 0, se.Size - 1
		if rg := r.Header.Get("X-Amz-Copy-Source-Range"); rg != "" {
			if _, err := fmt.Sscanf(rg, "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= se.Size || start > end {
				s.writeError(w, r, &s3Error{400, "InvalidRange", "invalid copy source range"})
				return
			}
		}
		rd.Seek(start, io.SeekStart)
		src = io.LimitReader(rd, end-start+1)
	} else {
		vb, err = s.body(r, ctx)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		src = vb
	}
	chunks, size, sum, err := s.Filer.UploadChunks(src, up.FullPath(), partName(n), "", cfg)
	if err != nil {
		s.writeError(w, r, mapUploadErr(err))
		return
	}
	if vb != nil {
		if err := vb.check(); err != nil {
			s.Filer.DeleteChunksAsync(chunks)
			s.writeError(w, r, err)
			return
		}
	}
	t := time.Now().UTC()
	if err := s.Filer.Save(&filer.Entry{Dir: up.FullPath(), Name: partName(n), Mode: 0o644, Mtime: t, Crtime: t, Size: size, MD5: sum, ETag: sum, Chunks: chunks}); err != nil {
		s.Filer.DeleteChunksAsync(chunks)
		s.writeError(w, r, err)
		return
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" {
		xmlResponse(w, 200, struct {
			XMLName      xml.Name `xml:"CopyPartResult"`
			LastModified string   `xml:"LastModified"`
			ETag         string   `xml:"ETag"`
		}{LastModified: t.Format("2006-01-02T15:04:05.000Z"), ETag: `"` + sum + `"`})
		return
	}
	w.Header().Set("ETag", `"`+sum+`"`)
	w.WriteHeader(200)
}

func (s *Server) completeMultipart(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	up, err := s.findUpload(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var req struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := xml.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil || len(req.Parts) == 0 {
		s.writeError(w, r, errMalformedXML)
		return
	}
	var chunks []filer.Chunk
	var off int64
	md5s := md5.New()
	prev := 0
	for _, p := range req.Parts {
		if p.PartNumber <= prev {
			s.writeError(w, r, &s3Error{400, "InvalidPartOrder", "The list of parts was not in ascending order."})
			return
		}
		prev = p.PartNumber
		pe, err := s.Filer.Find(up.FullPath() + "/" + partName(p.PartNumber))
		if err != nil || strings.Trim(p.ETag, `"`) != pe.ETag {
			s.writeError(w, r, errInvalidPart)
			return
		}
		raw, _ := hex.DecodeString(pe.ETag)
		md5s.Write(raw)
		for _, c := range pe.Chunks {
			c.Offset += off
			chunks = append(chunks, c)
		}
		off += pe.Size
	}
	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(md5s.Sum(nil)), len(req.Parts))
	dst := objectPath(ctx.bucket, ctx.key)
	dir, name := path.Split(dst)
	dir = strings.TrimSuffix(dir, "/")
	t := time.Now().UTC()
	ext := map[string]string{}
	for k, v := range up.Extended {
		if !strings.HasPrefix(k, "s3:") || k == "s3:tagging" {
			ext[k] = v
		}
	}
	e := &filer.Entry{Dir: dir, Name: name, Mode: 0o644, Mtime: t, Crtime: t, Mime: up.Extended["s3:mime"], Size: off, ETag: etag, Chunks: chunks, Extended: ext, Owner: ownerOf(ctx), TTL: s.Filer.EffectiveConfig(dir).TTL}
	// chunks of parts not listed in the completion must be freed
	used := map[string]bool{}
	for _, c := range chunks {
		used[c.Fid] = true
	}
	var orphans []filer.Chunk
	s.Filer.Walk(up.FullPath(), func(pe *filer.Entry) {
		for _, c := range pe.Chunks {
			if !used[c.Fid] {
				orphans = append(orphans, c)
			}
		}
	})
	if err := s.Filer.Save(e); err != nil {
		s.writeError(w, r, mapUploadErr(err))
		return
	}
	s.Filer.DeleteMetaOnly(up.FullPath(), true)
	s.Filer.DeleteChunksAsync(orphans)
	setSSEHeaders(w, e)
	xmlResponse(w, 200, struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		NS       string   `xml:"xmlns,attr"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Location: "/" + ctx.bucket + "/" + ctx.key, Bucket: ctx.bucket, Key: ctx.key, ETag: `"` + etag + `"`})
}

func (s *Server) abortMultipart(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapCreate, vault.CapUpdate, vault.CapDelete) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	up, err := s.findUpload(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.Filer.Delete(up.FullPath(), true); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) listParts(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.allowed(ctx, aclPath(ctx.bucket, ctx.key), vault.CapRead, vault.CapCreate, vault.CapUpdate) {
		s.writeError(w, r, errAccessDenied)
		return
	}
	up, err := s.findUpload(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	marker, _ := strconv.Atoi(ctx.q.Get("part-number-marker"))
	maxParts := 1000
	if v, err := strconv.Atoi(ctx.q.Get("max-parts")); err == nil && v > 0 && v < maxParts {
		maxParts = v
	}
	type part struct {
		PartNumber   int    `xml:"PartNumber"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}
	entries, _, _ := s.Filer.List(up.FullPath(), filer.ListOptions{ShowHidden: true})
	var parts []part
	truncated := false
	next := 0
	for _, e := range entries {
		n, err := strconv.Atoi(strings.TrimSuffix(e.Name, ".part"))
		if err != nil || n <= marker {
			continue
		}
		if len(parts) >= maxParts {
			truncated = true
			break
		}
		parts = append(parts, part{n, e.Mtime.Format("2006-01-02T15:04:05.000Z"), `"` + e.ETag + `"`, e.Size})
		next = n
	}
	xmlResponse(w, 200, struct {
		XMLName              xml.Name `xml:"ListPartsResult"`
		NS                   string   `xml:"xmlns,attr"`
		Bucket               string   `xml:"Bucket"`
		Key                  string   `xml:"Key"`
		UploadID             string   `xml:"UploadId"`
		PartNumberMarker     int      `xml:"PartNumberMarker"`
		NextPartNumberMarker int      `xml:"NextPartNumberMarker"`
		MaxParts             int      `xml:"MaxParts"`
		IsTruncated          bool     `xml:"IsTruncated"`
		StorageClass         string   `xml:"StorageClass"`
		Parts                []part   `xml:"Part"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: ctx.bucket, Key: ctx.key, UploadID: ctx.q.Get("uploadId"), PartNumberMarker: marker, NextPartNumberMarker: next, MaxParts: maxParts, IsTruncated: truncated, StorageClass: "STANDARD", Parts: parts})
}

func (s *Server) listMultipartUploads(w http.ResponseWriter, r *http.Request, ctx *reqCtx) {
	if !s.bucketExists(w, r, ctx, vault.CapList, vault.CapRead) {
		return
	}
	type upload struct {
		Key       string `xml:"Key"`
		UploadID  string `xml:"UploadId"`
		Initiated string `xml:"Initiated"`
	}
	prefix := ctx.q.Get("prefix")
	entries, _, _ := s.Filer.List(filer.BucketsDir+"/"+ctx.bucket+"/.uploads", filer.ListOptions{ShowHidden: true})
	var ups []upload
	for _, e := range entries {
		k := e.Extended["s3:key"]
		if e.IsDir && strings.HasPrefix(k, prefix) {
			ups = append(ups, upload{k, e.Name, e.Crtime.Format("2006-01-02T15:04:05.000Z")})
		}
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].Key < ups[j].Key })
	xmlResponse(w, 200, struct {
		XMLName     xml.Name `xml:"ListMultipartUploadsResult"`
		NS          string   `xml:"xmlns,attr"`
		Bucket      string   `xml:"Bucket"`
		Prefix      string   `xml:"Prefix"`
		MaxUploads  int      `xml:"MaxUploads"`
		IsTruncated bool     `xml:"IsTruncated"`
		Uploads     []upload `xml:"Upload"`
	}{NS: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: ctx.bucket, Prefix: prefix, MaxUploads: 1000, Uploads: ups})
}

var _ = bytes.NewReader
