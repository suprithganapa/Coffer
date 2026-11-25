package s3api

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	algoV4               = "AWS4-HMAC-SHA256"
	unsignedPayload      = "UNSIGNED-PAYLOAD"
	streamingSigned      = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingTrail       = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	streamingSignedTrail = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	emptySHA256          = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	maxClockSkew         = 15 * time.Minute
)

// sigV4 holds the parsed authorization of a request.
type sigV4 struct {
	AccessKey     string
	Date          string // yyyymmdd
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	AmzDate       string // yyyymmddThhmmssZ
	Presigned     bool
	Expires       time.Duration
}

func (s *sigV4) scope() string {
	return s.Date + "/" + s.Region + "/" + s.Service + "/aws4_request"
}

var errAuthHeaderMalformed = errors.New("AuthorizationHeaderMalformed")

func parseCredential(cred string, s *sigV4) error {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return errAuthHeaderMalformed
	}
	s.AccessKey, s.Date, s.Region, s.Service = parts[0], parts[1], parts[2], parts[3]
	return nil
}

// parseSigV4 extracts header or query (presigned) authentication.
func parseSigV4(r *http.Request) (*sigV4, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		if !strings.HasPrefix(h, algoV4+" ") {
			return nil, errors.New("unsupported authorization scheme (only AWS Signature Version 4 is supported)")
		}
		s := &sigV4{}
		for _, kv := range strings.Split(strings.TrimPrefix(h, algoV4+" "), ",") {
			kv = strings.TrimSpace(kv)
			i := strings.IndexByte(kv, '=')
			if i < 0 {
				return nil, errAuthHeaderMalformed
			}
			k, v := kv[:i], kv[i+1:]
			switch k {
			case "Credential":
				if err := parseCredential(v, s); err != nil {
					return nil, err
				}
			case "SignedHeaders":
				s.SignedHeaders = strings.Split(v, ";")
			case "Signature":
				s.Signature = v
			}
		}
		s.AmzDate = r.Header.Get("X-Amz-Date")
		if s.AmzDate == "" {
			if d := r.Header.Get("Date"); d != "" {
				if t, err := http.ParseTime(d); err == nil {
					s.AmzDate = t.UTC().Format("20060102T150405Z")
				}
			}
		}
		if s.AccessKey == "" || s.Signature == "" || len(s.SignedHeaders) == 0 || s.AmzDate == "" {
			return nil, errAuthHeaderMalformed
		}
		return s, nil
	}
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") == "" {
		return nil, nil // anonymous
	}
	if q.Get("X-Amz-Algorithm") != algoV4 {
		return nil, errors.New("unsupported presign algorithm")
	}
	s := &sigV4{Presigned: true, AmzDate: q.Get("X-Amz-Date"), Signature: q.Get("X-Amz-Signature")}
	if err := parseCredential(q.Get("X-Amz-Credential"), s); err != nil {
		return nil, err
	}
	s.SignedHeaders = strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	exp, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || exp < 1 || exp > 7*24*3600 {
		return nil, errors.New("invalid X-Amz-Expires")
	}
	s.Expires = time.Duration(exp) * time.Second
	return s, nil
}

// awsEncode is RFC 3986 encoding as required by SigV4.
func awsEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encodeSlash) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(u *url.URL, presigned bool) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEncode(k, true)+"="+awsEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalHeaders(r *http.Request, signed []string) string {
	var b strings.Builder
	for _, h := range signed {
		var v string
		switch h {
		case "host":
			v = r.Host
		case "content-length":
			v = r.Header.Get("Content-Length")
			if v == "" && r.ContentLength >= 0 {
				v = strconv.FormatInt(r.ContentLength, 10)
			}
		default:
			vals := r.Header.Values(http.CanonicalHeaderKey(h))
			for i := range vals {
				vals[i] = strings.Join(strings.Fields(vals[i]), " ")
			}
			v = strings.Join(vals, ",")
		}
		b.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// payloadHash returns the hash used in the canonical request.
func payloadHash(r *http.Request, s *sigV4) string {
	if s.Presigned {
		if v := r.URL.Query().Get("X-Amz-Content-Sha256"); v != "" {
			return v
		}
		return unsignedPayload
	}
	if v := r.Header.Get("X-Amz-Content-Sha256"); v != "" {
		return v
	}
	return emptySHA256
}

func buildCanonicalRequest(r *http.Request, s *sigV4) string {
	uri := awsEncode(r.URL.Path, false)
	if uri == "" {
		uri = "/"
	}
	return strings.Join([]string{
		r.Method, uri, canonicalQuery(r.URL, s.Presigned),
		canonicalHeaders(r, s.SignedHeaders), strings.Join(s.SignedHeaders, ";"), payloadHash(r, s),
	}, "\n")
}

func computeSignature(secret string, s *sigV4, canonical string) string {
	sts := algoV4 + "\n" + s.AmzDate + "\n" + s.scope() + "\n" + sha256Hex([]byte(canonical))
	return hex.EncodeToString(hmacSHA256(signingKey(secret, s.Date, s.Region, s.Service), sts))
}

// verify checks the signature and time window.
func (s *sigV4) verify(r *http.Request, secret string) error {
	t, err := time.Parse("20060102T150405Z", s.AmzDate)
	if err != nil {
		return errors.New("AccessDenied: invalid X-Amz-Date")
	}
	if !strings.HasPrefix(s.AmzDate, s.Date) {
		return errors.New("AuthorizationHeaderMalformed: date mismatch")
	}
	if s.Presigned {
		if time.Now().After(t.Add(s.Expires)) {
			return errors.New("AccessDenied: Request has expired")
		}
		if t.After(time.Now().Add(maxClockSkew)) {
			return errors.New("RequestTimeTooSkewed")
		}
	} else if d := time.Since(t); d > maxClockSkew || d < -maxClockSkew {
		return errors.New("RequestTimeTooSkewed")
	}
	want := computeSignature(secret, s, buildCanonicalRequest(r, s))
	if !hmac.Equal([]byte(want), []byte(s.Signature)) {
		return errors.New("SignatureDoesNotMatch")
	}
	return nil
}

// ---------------- aws-chunked decoding ----------------

// chunkedReader decodes "aws-chunked" bodies, verifying chunk signatures
// when the payload is signed.
type chunkedReader struct {
	r       *bufio.Reader
	buf     []byte
	done    bool
	signed  bool
	prevSig string
	key     []byte
	s       *sigV4
	err     error
}

func newChunkedReader(body io.Reader, s *sigV4, secret string, signed bool) *chunkedReader {
	cr := &chunkedReader{r: bufio.NewReaderSize(body, 64<<10), signed: signed, s: s}
	if signed {
		cr.prevSig = s.Signature
		cr.key = signingKey(secret, s.Date, s.Region, s.Service)
	}
	return cr
}

var errChunkSig = errors.New("SignatureDoesNotMatch: chunk signature mismatch")

func (c *chunkedReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *chunkedReader) next() error {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("malformed aws-chunked body: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	sizeStr, sig := line, ""
	if i := strings.IndexByte(line, ';'); i >= 0 {
		sizeStr = line[:i]
		ext := line[i+1:]
		if strings.HasPrefix(ext, "chunk-signature=") {
			sig = strings.TrimPrefix(ext, "chunk-signature=")
		}
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
	if err != nil || size < 0 || size > 64<<20 {
		return errors.New("malformed aws-chunked chunk size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.r, data); err != nil {
		return fmt.Errorf("truncated aws-chunked body: %w", err)
	}
	if c.signed {
		sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.s.AmzDate + "\n" + c.s.scope() + "\n" + c.prevSig + "\n" + emptySHA256 + "\n" + sha256Hex(data)
		want := hex.EncodeToString(hmacSHA256(c.key, sts))
		if !hmac.Equal([]byte(want), []byte(sig)) {
			return errChunkSig
		}
		c.prevSig = sig
	}
	if size == 0 {
		// consume optional trailers until blank line / EOF
		for {
			l, err := c.r.ReadString('\n')
			if err != nil || strings.TrimRight(l, "\r\n") == "" {
				break
			}
		}
		c.done = true
		return nil
	}
	// trailing CRLF after data
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(c.r, crlf); err != nil || string(crlf) != "\r\n" {
		return errors.New("malformed aws-chunked chunk terminator")
	}
	c.buf = data
	return nil
}

var cryptoRand = rand.Reader
