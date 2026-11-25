package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CodedError carries an HTTP status code.
type CodedError struct {
	Code int
	Msg  string
}

func (e *CodedError) Error() string { return e.Msg }

func errCode(code int, format string, a ...any) error {
	return &CodedError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

var (
	ErrPermissionDenied = &CodedError{403, "permission denied"}
	ErrSealed           = &CodedError{503, "Coffer is sealed"}
	ErrNotInitialized   = &CodedError{503, "Coffer is not initialized"}
)

func badRequest(format string, a ...any) error { return errCode(400, format, a...) }

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randomString(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(base62)))
	for i := range b {
		v, _ := rand.Int(rand.Reader, max)
		b[i] = base62[v.Int64()]
	}
	return string(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func uuid() string {
	b := randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---- request data accessors (accept JSON numbers, strings, lists) ----

func dString(d map[string]any, k string) string {
	switch v := d[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []any:
		if len(v) > 0 {
			return fmt.Sprint(v[0])
		}
	}
	return ""
}

func dInt(d map[string]any, k string, def int) int {
	switch v := d[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		i, err := v.Int64()
		if err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	case []string:
		if len(v) > 0 {
			if i, err := strconv.Atoi(v[0]); err == nil {
				return i
			}
		}
	}
	return def
}

func dBool(d map[string]any, k string, def bool) bool {
	switch v := d[k].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	case []string:
		if len(v) > 0 {
			if b, err := strconv.ParseBool(v[0]); err == nil {
				return b
			}
		}
	case float64:
		return v != 0
	}
	return def
}

func has(d map[string]any, k string) bool { _, ok := d[k]; return ok }

// dStrings accepts a list or a comma separated string.
func dStrings(d map[string]any, k string) []string {
	var out []string
	switch v := d[k].(type) {
	case string:
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	case []string:
		for _, p := range v {
			out = append(out, strings.Split(p, ",")...)
		}
	case []any:
		for _, p := range v {
			if s := strings.TrimSpace(fmt.Sprint(p)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func dInts(d map[string]any, k string) []int {
	var out []int
	switch v := d[k].(type) {
	case []any:
		for _, p := range v {
			switch n := p.(type) {
			case float64:
				out = append(out, int(n))
			case string:
				if i, err := strconv.Atoi(n); err == nil {
					out = append(out, i)
				}
			case json.Number:
				if i, err := n.Int64(); err == nil {
					out = append(out, int(i))
				}
			}
		}
	case string:
		for _, p := range strings.Split(v, ",") {
			if i, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				out = append(out, i)
			}
		}
	case float64:
		out = append(out, int(v))
	}
	return out
}

// ParseDuration accepts "90", "90s", "15m", "24h", "7d".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if i, err := strconv.Atoi(s); err == nil {
		return time.Duration(i) * time.Second, nil
	}
	if strings.HasSuffix(s, "d") {
		if i, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil {
			return time.Duration(i) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

func dDuration(d map[string]any, k string, def time.Duration) (time.Duration, error) {
	v, ok := d[k]
	if !ok || v == nil {
		return def, nil
	}
	switch n := v.(type) {
	case float64:
		return time.Duration(n) * time.Second, nil
	case json.Number:
		i, err := n.Int64()
		return time.Duration(i) * time.Second, err
	}
	s := dString(d, k)
	if s == "" {
		return def, nil
	}
	dur, err := ParseDuration(s)
	if err != nil {
		return 0, badRequest("invalid duration for %s: %q", k, s)
	}
	return dur, nil
}

func uniqSorted(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func listResponse(keys []string) *Response {
	if keys == nil {
		keys = []string{}
	}
	return &Response{Data: map[string]any{"keys": keys}}
}

func now() time.Time { return time.Now().UTC() }

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func toMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}
