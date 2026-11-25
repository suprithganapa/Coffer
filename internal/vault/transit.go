package vault

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// transitBackend provides encryption as a service. Keys never leave the
// barrier (unless created exportable). Ciphertexts are "coffer:v<N>:<b64>".
type transitBackend struct {
	view *View
	mu   sync.Mutex
}

type transitKeyVersion struct {
	Key          []byte    `json:"key"`      // symmetric key or private key (DER/seed)
	HMACKey      []byte    `json:"hmac_key"` // separate key for hmac/
	PublicKey    string    `json:"public_key,omitempty"`
	CreationTime time.Time `json:"creation_time"`
}

type transitKey struct {
	Name                 string                       `json:"name"`
	Type                 string                       `json:"type"`
	Derived              bool                         `json:"derived"`
	Exportable           bool                         `json:"exportable"`
	DeletionAllowed      bool                         `json:"deletion_allowed"`
	LatestVersion        int                          `json:"latest_version"`
	MinDecryptionVersion int                          `json:"min_decryption_version"`
	MinEncryptionVersion int                          `json:"min_encryption_version"`
	AutoRotatePeriod     time.Duration                `json:"auto_rotate_period"`
	Versions             map[string]transitKeyVersion `json:"versions"`
	CreatedAt            time.Time                    `json:"created_at"`
}

var transitTypes = map[string]bool{"aes256-gcm96": true, "aes128-gcm96": true, "ed25519": true, "ecdsa-p256": true, "hmac": true}

var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9_\-.]+$`)

func (k *transitKey) supportsEncryption() bool {
	return k.Type == "aes256-gcm96" || k.Type == "aes128-gcm96"
}

func (k *transitKey) supportsSigning() bool {
	return k.Type == "ed25519" || k.Type == "ecdsa-p256"
}

func newKeyVersion(typ string) (transitKeyVersion, error) {
	v := transitKeyVersion{HMACKey: randomBytes(32), CreationTime: now()}
	switch typ {
	case "aes256-gcm96", "hmac":
		v.Key = randomBytes(32)
	case "aes128-gcm96":
		v.Key = randomBytes(16)
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return v, err
		}
		v.Key = priv.Seed()
		v.PublicKey = base64.StdEncoding.EncodeToString(pub)
	case "ecdsa-p256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return v, err
		}
		der, _ := x509.MarshalECPrivateKey(priv)
		v.Key = der
		pubDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		v.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
	default:
		return v, badRequest("unsupported key type %q", typ)
	}
	return v, nil
}

func (b *transitBackend) getKey(name string) (*transitKey, error) {
	var k transitKey
	ok, err := b.view.GetJSON("policy/"+name, &k)
	if err != nil || !ok {
		return nil, err
	}
	return &k, nil
}

func (b *transitBackend) mustKey(name string) (*transitKey, error) {
	k, err := b.getKey(name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, badRequest("encryption key %q not found", name)
	}
	return k, nil
}

func (b *transitBackend) putKey(k *transitKey) error { return b.view.PutJSON("policy/"+k.Name, k) }

func (b *transitBackend) Exists(req *Request) (bool, error) {
	parts := strings.Split(req.RelPath, "/")
	if len(parts) == 2 && parts[0] == "keys" {
		k, err := b.getKey(parts[1])
		return k != nil, err
	}
	return true, nil // encrypt/decrypt/etc. are "update"
}

// CreateKey creates a key if it doesn't exist (used internally by the filer).
func (b *transitBackend) CreateKey(name, typ string) (*transitKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if k, err := b.getKey(name); err != nil || k != nil {
		return k, err
	}
	if typ == "" {
		typ = "aes256-gcm96"
	}
	if !transitTypes[typ] {
		return nil, badRequest("unsupported key type %q", typ)
	}
	if !keyNameRe.MatchString(name) {
		return nil, badRequest("invalid key name")
	}
	v, err := newKeyVersion(typ)
	if err != nil {
		return nil, err
	}
	k := &transitKey{Name: name, Type: typ, LatestVersion: 1, MinDecryptionVersion: 1, Versions: map[string]transitKeyVersion{"1": v}, CreatedAt: now()}
	return k, b.putKey(k)
}

func (b *transitBackend) Handle(req *Request) (*Response, error) {
	parts := strings.Split(strings.Trim(req.RelPath, "/"), "/")
	d := req.Data
	switch parts[0] {
	case "keys":
		if len(parts) == 1 {
			keys, err := b.view.List("policy/")
			if err != nil {
				return nil, err
			}
			return listResponse(keys), nil
		}
		name := parts[1]
		if len(parts) == 3 {
			switch parts[2] {
			case "rotate":
				return b.rotate(name)
			case "config":
				return b.configKey(name, d)
			case "trim":
				return b.trim(name, d)
			}
			return nil, errCode(404, "unsupported path")
		}
		switch req.Operation {
		case OpRead:
			k, err := b.getKey(name)
			if err != nil || k == nil {
				return nil, err
			}
			return &Response{Data: keyInfo(k)}, nil
		case OpCreate, OpUpdate:
			typ := dString(d, "type")
			if typ == "" {
				typ = "aes256-gcm96"
			}
			b.mu.Lock()
			existing, _ := b.getKey(name)
			b.mu.Unlock()
			if existing != nil {
				return &Response{Data: keyInfo(existing)}, nil
			}
			k, err := b.CreateKey(name, typ)
			if err != nil {
				return nil, err
			}
			k.Derived = dBool(d, "derived", false)
			k.Exportable = dBool(d, "exportable", false)
			if ap, err := dDuration(d, "auto_rotate_period", 0); err == nil {
				k.AutoRotatePeriod = ap
			}
			if k.Derived && !k.supportsEncryption() {
				return nil, badRequest("key derivation is only supported for encryption keys")
			}
			if err := b.putKey(k); err != nil {
				return nil, err
			}
			return &Response{Data: keyInfo(k)}, nil
		case OpDelete:
			k, err := b.mustKey(name)
			if err != nil {
				return nil, err
			}
			if !k.DeletionAllowed {
				return nil, badRequest("deletion is not allowed for this key; set deletion_allowed=true via keys/%s/config first", name)
			}
			return &Response{StatusCode: 204}, b.view.Delete("policy/" + name)
		}
	case "encrypt":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		return b.batch(req, parts[1], b.encryptOne)
	case "decrypt":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		return b.batch(req, parts[1], b.decryptOne)
	case "rewrap":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		return b.batch(req, parts[1], b.rewrapOne)
	case "datakey":
		if len(parts) < 3 {
			return nil, badRequest("use datakey/plaintext/<name> or datakey/wrapped/<name>")
		}
		return b.datakey(parts[2], parts[1] == "plaintext", d)
	case "hmac":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		algo := dString(d, "algorithm")
		if len(parts) > 2 {
			algo = parts[2]
		}
		return b.hmacOp(parts[1], algo, d)
	case "sign":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		return b.sign(parts[1], d)
	case "verify":
		if len(parts) < 2 {
			return nil, badRequest("key name required")
		}
		algo := dString(d, "algorithm")
		if len(parts) > 2 {
			algo = parts[2]
		}
		return b.verify(parts[1], algo, d)
	case "export":
		if len(parts) < 3 {
			return nil, badRequest("use export/<encryption-key|signing-key|hmac-key>/<name>")
		}
		return b.export(parts[1], parts[2])
	case "random":
		n := dInt(d, "bytes", 32)
		if len(parts) > 1 {
			n, _ = strconv.Atoi(parts[1])
		}
		if n < 1 || n > 1<<20 {
			return nil, badRequest("bytes must be between 1 and 1048576")
		}
		return &Response{Data: map[string]any{"random_bytes": encodeFmt(randomBytes(n), dString(d, "format"))}}, nil
	case "hash":
		algo := dString(d, "algorithm")
		if len(parts) > 1 {
			algo = parts[1]
		}
		in, err := base64.StdEncoding.DecodeString(dString(d, "input"))
		if err != nil {
			return nil, badRequest("input must be base64")
		}
		h, err := hasher(algo)
		if err != nil {
			return nil, err
		}
		hh := h()
		hh.Write(in)
		f := dString(d, "format")
		if f == "" {
			f = "hex"
		}
		return &Response{Data: map[string]any{"sum": encodeFmt(hh.Sum(nil), f)}}, nil
	}
	return nil, errCode(404, "unsupported transit path %q", req.RelPath)
}

func encodeFmt(b []byte, f string) string {
	if f == "hex" {
		return hex.EncodeToString(b)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hasher(algo string) (func() hash.Hash, error) {
	switch algo {
	case "", "sha2-256":
		return sha256.New, nil
	case "sha2-384":
		return sha512.New384, nil
	case "sha2-512":
		return sha512.New, nil
	}
	return nil, badRequest("unsupported algorithm %q", algo)
}

func keyInfo(k *transitKey) map[string]any {
	keys := map[string]any{}
	for ver, v := range k.Versions {
		if v.PublicKey != "" {
			keys[ver] = map[string]any{"public_key": v.PublicKey, "creation_time": v.CreationTime}
		} else {
			keys[ver] = v.CreationTime.Unix()
		}
	}
	return map[string]any{
		"name": k.Name, "type": k.Type, "derived": k.Derived, "exportable": k.Exportable,
		"deletion_allowed": k.DeletionAllowed, "latest_version": k.LatestVersion,
		"min_decryption_version": k.MinDecryptionVersion, "min_encryption_version": k.MinEncryptionVersion,
		"keys": keys, "supports_encryption": k.supportsEncryption(), "supports_decryption": k.supportsEncryption(),
		"supports_signing": k.supportsSigning(), "auto_rotate_period": int(k.AutoRotatePeriod.Seconds()),
		"created_at": k.CreatedAt,
	}
}

func (b *transitBackend) rotate(name string) (*Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	v, err := newKeyVersion(k.Type)
	if err != nil {
		return nil, err
	}
	k.LatestVersion++
	k.Versions[strconv.Itoa(k.LatestVersion)] = v
	if err := b.putKey(k); err != nil {
		return nil, err
	}
	return &Response{Data: keyInfo(k)}, nil
}

func (b *transitBackend) configKey(name string, d map[string]any) (*Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	if has(d, "min_decryption_version") {
		v := dInt(d, "min_decryption_version", 1)
		if v < 1 || v > k.LatestVersion {
			return nil, badRequest("min_decryption_version must be between 1 and %d", k.LatestVersion)
		}
		k.MinDecryptionVersion = v
	}
	if has(d, "min_encryption_version") {
		v := dInt(d, "min_encryption_version", 0)
		if v < 0 || v > k.LatestVersion {
			return nil, badRequest("invalid min_encryption_version")
		}
		k.MinEncryptionVersion = v
	}
	if has(d, "deletion_allowed") {
		k.DeletionAllowed = dBool(d, "deletion_allowed", false)
	}
	if has(d, "exportable") {
		if k.Exportable && !dBool(d, "exportable", false) {
			return nil, badRequest("exportable cannot be disabled once enabled")
		}
		k.Exportable = dBool(d, "exportable", false)
	}
	if has(d, "auto_rotate_period") {
		ap, err := dDuration(d, "auto_rotate_period", 0)
		if err != nil {
			return nil, err
		}
		k.AutoRotatePeriod = ap
	}
	if err := b.putKey(k); err != nil {
		return nil, err
	}
	return &Response{Data: keyInfo(k)}, nil
}

func (b *transitBackend) trim(name string, d map[string]any) (*Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	min := dInt(d, "min_available_version", 0)
	if min < 1 || min > k.MinDecryptionVersion {
		return nil, badRequest("min_available_version must be between 1 and min_decryption_version (%d)", k.MinDecryptionVersion)
	}
	for ver := range k.Versions {
		if n, _ := strconv.Atoi(ver); n < min {
			delete(k.Versions, ver)
		}
	}
	return &Response{Data: keyInfo(k)}, b.putKey(k)
}

// aeadFor returns the cipher for a key version, deriving with context if needed.
func (k *transitKey) aead(ver int, context []byte) (cipher.AEAD, error) {
	kv, ok := k.Versions[strconv.Itoa(ver)]
	if !ok {
		return nil, badRequest("key version %d not available", ver)
	}
	key := kv.Key
	if k.Derived {
		if len(context) == 0 {
			return nil, badRequest("missing 'context' for key derivation; the key was created with derived=true")
		}
		dk, err := hkdf.Key(sha256.New, kv.Key, nil, string(context), len(kv.Key))
		if err != nil {
			return nil, err
		}
		key = dk
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type batchFn func(k *transitKey, item map[string]any) (map[string]any, error)

func (b *transitBackend) batch(req *Request, name string, fn batchFn) (*Response, error) {
	k, err := b.getKey(name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		// Vault auto-creates on encrypt; we do the same for convenience.
		if strings.HasPrefix(req.RelPath, "encrypt/") {
			if k, err = b.CreateKey(name, "aes256-gcm96"); err != nil {
				return nil, err
			}
		} else {
			return nil, badRequest("encryption key %q not found", name)
		}
	}
	if !k.supportsEncryption() {
		return nil, badRequest("key type %s does not support encryption", k.Type)
	}
	if items, ok := req.Data["batch_input"].([]any); ok {
		var results []map[string]any
		for _, it := range items {
			m, _ := it.(map[string]any)
			if m == nil {
				results = append(results, map[string]any{"error": "invalid batch item"})
				continue
			}
			r, err := fn(k, m)
			if err != nil {
				r = map[string]any{"error": err.Error()}
			}
			results = append(results, r)
		}
		return &Response{Data: map[string]any{"batch_results": results}}, nil
	}
	r, err := fn(k, req.Data)
	if err != nil {
		return nil, err
	}
	return &Response{Data: r}, nil
}

func decodeContext(d map[string]any) ([]byte, error) {
	c := dString(d, "context")
	if c == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return nil, badRequest("context must be base64")
	}
	return b, nil
}

func (b *transitBackend) encryptOne(k *transitKey, d map[string]any) (map[string]any, error) {
	pt, err := base64.StdEncoding.DecodeString(dString(d, "plaintext"))
	if err != nil {
		return nil, badRequest("plaintext must be base64 encoded")
	}
	ctx, err := decodeContext(d)
	if err != nil {
		return nil, err
	}
	ct, ver, err := k.encrypt(pt, ctx, dInt(d, "key_version", 0))
	if err != nil {
		return nil, err
	}
	return map[string]any{"ciphertext": ct, "key_version": ver}, nil
}

func (k *transitKey) encrypt(pt, ctx []byte, ver int) (string, int, error) {
	if ver == 0 {
		ver = k.LatestVersion
	}
	if ver < k.MinEncryptionVersion || ver > k.LatestVersion {
		return "", 0, badRequest("requested key version %d is not allowed for encryption", ver)
	}
	a, err := k.aead(ver, ctx)
	if err != nil {
		return "", 0, err
	}
	nonce := randomBytes(a.NonceSize())
	ct := a.Seal(nonce, nonce, pt, nil)
	return fmt.Sprintf("coffer:v%d:%s", ver, base64.StdEncoding.EncodeToString(ct)), ver, nil
}

func parseCiphertext(s string) (int, []byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || (parts[0] != "coffer" && parts[0] != "vault") || !strings.HasPrefix(parts[1], "v") {
		return 0, nil, badRequest("invalid ciphertext: expected coffer:v<N>:<base64>")
	}
	ver, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return 0, nil, badRequest("invalid ciphertext version")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, badRequest("invalid ciphertext encoding")
	}
	return ver, raw, nil
}

func (k *transitKey) decrypt(ct string, ctx []byte) ([]byte, int, error) {
	ver, raw, err := parseCiphertext(ct)
	if err != nil {
		return nil, 0, err
	}
	if ver < k.MinDecryptionVersion {
		return nil, 0, badRequest("ciphertext key version %d is below min_decryption_version %d", ver, k.MinDecryptionVersion)
	}
	a, err := k.aead(ver, ctx)
	if err != nil {
		return nil, 0, err
	}
	if len(raw) < a.NonceSize() {
		return nil, 0, badRequest("ciphertext too short")
	}
	pt, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], nil)
	if err != nil {
		return nil, 0, badRequest("decryption failed: message authentication failed")
	}
	return pt, ver, nil
}

func (b *transitBackend) decryptOne(k *transitKey, d map[string]any) (map[string]any, error) {
	ctx, err := decodeContext(d)
	if err != nil {
		return nil, err
	}
	pt, _, err := k.decrypt(dString(d, "ciphertext"), ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}, nil
}

func (b *transitBackend) rewrapOne(k *transitKey, d map[string]any) (map[string]any, error) {
	ctx, err := decodeContext(d)
	if err != nil {
		return nil, err
	}
	pt, _, err := k.decrypt(dString(d, "ciphertext"), ctx)
	if err != nil {
		return nil, err
	}
	ct, ver, err := k.encrypt(pt, ctx, dInt(d, "key_version", 0))
	if err != nil {
		return nil, err
	}
	return map[string]any{"ciphertext": ct, "key_version": ver}, nil
}

func (b *transitBackend) datakey(name string, plaintext bool, d map[string]any) (*Response, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	if !k.supportsEncryption() {
		return nil, badRequest("key type %s does not support data keys", k.Type)
	}
	bits := dInt(d, "bits", 256)
	if bits != 128 && bits != 256 && bits != 512 {
		return nil, badRequest("bits must be 128, 256 or 512")
	}
	ctx, err := decodeContext(d)
	if err != nil {
		return nil, err
	}
	dk := randomBytes(bits / 8)
	ct, ver, err := k.encrypt(dk, ctx, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ciphertext": ct, "key_version": ver}
	if plaintext {
		out["plaintext"] = base64.StdEncoding.EncodeToString(dk)
	}
	return &Response{Data: out}, nil
}

// GenerateDataKey / UnwrapDataKey are used by the filer for envelope encryption.
func (b *transitBackend) GenerateDataKey(name string, ctx []byte) (plain []byte, wrapped string, err error) {
	k, err := b.getKey(name)
	if err != nil {
		return nil, "", err
	}
	if k == nil {
		if k, err = b.CreateKey(name, "aes256-gcm96"); err != nil {
			return nil, "", err
		}
	}
	if !k.supportsEncryption() {
		return nil, "", badRequest("key %q (type %s) cannot be used for encryption", name, k.Type)
	}
	dk := randomBytes(32)
	ct, _, err := k.encrypt(dk, ctx, 0)
	return dk, ct, err
}

func (b *transitBackend) UnwrapDataKey(name, wrapped string, ctx []byte) ([]byte, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	pt, _, err := k.decrypt(wrapped, ctx)
	return pt, err
}

func (b *transitBackend) hmacOp(name, algo string, d map[string]any) (*Response, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	h, err := hasher(algo)
	if err != nil {
		return nil, err
	}
	in, err := base64.StdEncoding.DecodeString(dString(d, "input"))
	if err != nil {
		return nil, badRequest("input must be base64")
	}
	ver := dInt(d, "key_version", k.LatestVersion)
	kv, ok := k.Versions[strconv.Itoa(ver)]
	if !ok {
		return nil, badRequest("invalid key version")
	}
	hk := kv.HMACKey
	if k.Type == "hmac" {
		hk = kv.Key
	}
	m := hmac.New(h, hk)
	m.Write(in)
	return &Response{Data: map[string]any{"hmac": fmt.Sprintf("coffer:v%d:%s", ver, base64.StdEncoding.EncodeToString(m.Sum(nil)))}}, nil
}

func (b *transitBackend) sign(name string, d map[string]any) (*Response, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	if !k.supportsSigning() {
		return nil, badRequest("key type %s does not support signing", k.Type)
	}
	in, err := base64.StdEncoding.DecodeString(dString(d, "input"))
	if err != nil {
		return nil, badRequest("input must be base64")
	}
	ver := k.LatestVersion
	kv := k.Versions[strconv.Itoa(ver)]
	var sig []byte
	switch k.Type {
	case "ed25519":
		sig = ed25519.Sign(ed25519.NewKeyFromSeed(kv.Key), in)
	case "ecdsa-p256":
		priv, err := x509.ParseECPrivateKey(kv.Key)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(in)
		sig, err = ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
	}
	return &Response{Data: map[string]any{"signature": fmt.Sprintf("coffer:v%d:%s", ver, base64.StdEncoding.EncodeToString(sig)), "key_version": ver}}, nil
}

func (b *transitBackend) verify(name, algo string, d map[string]any) (*Response, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	in, err := base64.StdEncoding.DecodeString(dString(d, "input"))
	if err != nil {
		return nil, badRequest("input must be base64")
	}
	if hm := dString(d, "hmac"); hm != "" {
		ver, mac, err := parseCiphertext(hm)
		if err != nil {
			return nil, err
		}
		kv, ok := k.Versions[strconv.Itoa(ver)]
		if !ok {
			return nil, badRequest("invalid key version")
		}
		h, err := hasher(algo)
		if err != nil {
			return nil, err
		}
		hk := kv.HMACKey
		if k.Type == "hmac" {
			hk = kv.Key
		}
		m := hmac.New(h, hk)
		m.Write(in)
		return &Response{Data: map[string]any{"valid": hmac.Equal(m.Sum(nil), mac)}}, nil
	}
	sigS := dString(d, "signature")
	if sigS == "" {
		return nil, badRequest("signature or hmac is required")
	}
	ver, sig, err := parseCiphertext(sigS)
	if err != nil {
		return nil, err
	}
	kv, ok := k.Versions[strconv.Itoa(ver)]
	if !ok {
		return nil, badRequest("invalid key version")
	}
	valid := false
	switch k.Type {
	case "ed25519":
		valid = ed25519.Verify(ed25519.NewKeyFromSeed(kv.Key).Public().(ed25519.PublicKey), in, sig)
	case "ecdsa-p256":
		priv, err := x509.ParseECPrivateKey(kv.Key)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(in)
		valid = ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig)
	default:
		return nil, badRequest("key type %s does not support signature verification", k.Type)
	}
	return &Response{Data: map[string]any{"valid": valid}}, nil
}

func (b *transitBackend) export(kind, name string) (*Response, error) {
	k, err := b.mustKey(name)
	if err != nil {
		return nil, err
	}
	if !k.Exportable {
		return nil, badRequest("key is not exportable")
	}
	keys := map[string]string{}
	var vers []string
	for v := range k.Versions {
		vers = append(vers, v)
	}
	sort.Strings(vers)
	for _, v := range vers {
		kv := k.Versions[v]
		switch kind {
		case "encryption-key":
			if !k.supportsEncryption() {
				return nil, badRequest("key does not support encryption")
			}
			keys[v] = base64.StdEncoding.EncodeToString(kv.Key)
		case "hmac-key":
			keys[v] = base64.StdEncoding.EncodeToString(kv.HMACKey)
		case "signing-key":
			if !k.supportsSigning() {
				return nil, badRequest("key does not support signing")
			}
			keys[v] = base64.StdEncoding.EncodeToString(kv.Key)
		default:
			return nil, badRequest("unknown export type %q", kind)
		}
	}
	return &Response{Data: map[string]any{"name": k.Name, "type": k.Type, "keys": keys}}, nil
}

var _ = crypto.SHA256
