package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ClusterAuth signs and verifies short-lived tokens used between Coffer
// components (filer -> master -> volume servers). When the secret is empty,
// verification is disabled (open cluster, for trusted networks only).
type ClusterAuth struct {
	Secret []byte
}

const AdminScope = "*"

// Sign returns a token granting access to scope (a file id, or "*" for admin).
func (a *ClusterAuth) Sign(scope string, ttl time.Duration) string {
	if a == nil || len(a.Secret) == 0 {
		return ""
	}
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	m := hmac.New(sha256.New, a.Secret)
	m.Write([]byte(exp + "|" + scope))
	return exp + "." + hex.EncodeToString(m.Sum(nil)) + "." + scope
}

// Verify checks a token for the given scope; admin tokens grant any scope.
func (a *ClusterAuth) Verify(token, scope string) bool {
	if a == nil || len(a.Secret) == 0 {
		return true
	}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	tokScope := parts[2]
	if tokScope != AdminScope && tokScope != scope {
		return false
	}
	m := hmac.New(sha256.New, a.Secret)
	m.Write([]byte(parts[0] + "|" + tokScope))
	want := hex.EncodeToString(m.Sum(nil))
	return hmac.Equal([]byte(want), []byte(parts[1]))
}

// Enabled reports whether tokens are enforced.
func (a *ClusterAuth) Enabled() bool { return a != nil && len(a.Secret) > 0 }

// TokenFromRequest extracts the bearer token or ?jwt= parameter.
func TokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.URL.Query().Get("jwt")
}

// SetAuth attaches a token to an outgoing request.
func (a *ClusterAuth) SetAuth(req *http.Request, scope string) {
	if t := a.Sign(scope, 5*time.Minute); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

// ParseTTL parses "30s", "5m", "3h", "7d", "2w", "1M", "1y" into seconds.
func ParseTTL(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	unit := s[len(s)-1]
	num := s[:len(s)-1]
	mult := int64(0)
	switch unit {
	case 's':
		mult = 1
	case 'm':
		mult = 60
	case 'h':
		mult = 3600
	case 'd':
		mult = 86400
	case 'w':
		mult = 7 * 86400
	case 'M':
		mult = 30 * 86400
	case 'y':
		mult = 365 * 86400
	default:
		num = s
		mult = 60 // bare number = minutes (SeaweedFS convention)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid ttl " + strconv.Quote(s))
	}
	v := n * mult
	if v > 0xFFFFFFFF {
		v = 0xFFFFFFFF
	}
	return uint32(v), nil
}
