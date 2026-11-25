package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"coffer/internal/kvstore"
)

// The barrier encrypts everything written through it with AES-256-GCM.
// The keyring (a list of terms/keys) is itself encrypted with the root key,
// which only exists in memory while unsealed (reconstructed from Shamir
// unseal key shares).

const (
	keyringPath    = "core/keyring"
	sealConfigPath = "core/seal-config"
	barrierPrefix  = "b/"
	barrierVersion = 1
)

type barrierKey struct {
	Term        uint32    `json:"term"`
	Value       []byte    `json:"value"`
	InstallTime time.Time `json:"install_time"`
}

type keyring struct {
	ActiveTerm uint32       `json:"active_term"`
	Keys       []barrierKey `json:"keys"`
}

// Barrier is the encrypted storage layer.
type Barrier struct {
	store   *kvstore.Store
	mu      sync.RWMutex
	rootKey []byte
	ring    *keyring
	aeads   map[uint32]cipher.AEAD
}

func NewBarrier(store *kvstore.Store) *Barrier { return &Barrier{store: store} }

func aeadFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealWith(key []byte, aad, plaintext []byte) ([]byte, error) {
	a, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(a.NonceSize())
	return append(nonce, a.Seal(nil, nonce, plaintext, aad)...), nil
}

func openWith(key []byte, aad, ct []byte) ([]byte, error) {
	a, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < a.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return a.Open(nil, ct[:a.NonceSize()], ct[a.NonceSize():], aad)
}

// Initialized reports whether a keyring exists.
func (b *Barrier) Initialized() bool {
	_, ok := b.store.Get(keyringPath)
	return ok
}

// Initialize creates a fresh keyring protected by rootKey.
func (b *Barrier) Initialize(rootKey []byte) error {
	if b.Initialized() {
		return errors.New("barrier already initialized")
	}
	ring := &keyring{ActiveTerm: 1, Keys: []barrierKey{{Term: 1, Value: randomBytes(32), InstallTime: now()}}}
	return b.persistKeyring(rootKey, ring)
}

func (b *Barrier) persistKeyring(rootKey []byte, ring *keyring) error {
	raw, _ := json.Marshal(ring)
	ct, err := sealWith(rootKey, []byte(keyringPath), raw)
	if err != nil {
		return err
	}
	return b.store.Put(keyringPath, ct)
}

// Unseal decrypts the keyring with rootKey.
func (b *Barrier) Unseal(rootKey []byte) error {
	ct, ok := b.store.Get(keyringPath)
	if !ok {
		return ErrNotInitialized
	}
	raw, err := openWith(rootKey, []byte(keyringPath), ct)
	if err != nil {
		return errors.New("invalid unseal key(s): could not decrypt keyring")
	}
	var ring keyring
	if err := json.Unmarshal(raw, &ring); err != nil {
		return err
	}
	aeads := map[uint32]cipher.AEAD{}
	for _, k := range ring.Keys {
		a, err := aeadFor(k.Value)
		if err != nil {
			return err
		}
		aeads[k.Term] = a
	}
	b.mu.Lock()
	b.rootKey = append([]byte(nil), rootKey...)
	b.ring = &ring
	b.aeads = aeads
	b.mu.Unlock()
	return nil
}

// Seal wipes keys from memory.
func (b *Barrier) Seal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.rootKey {
		b.rootKey[i] = 0
	}
	if b.ring != nil {
		for _, k := range b.ring.Keys {
			for i := range k.Value {
				k.Value[i] = 0
			}
		}
	}
	b.rootKey, b.ring, b.aeads = nil, nil, nil
}

func (b *Barrier) Sealed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ring == nil
}

// Rotate installs a new encryption term. Old terms stay for decryption.
func (b *Barrier) Rotate() (uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ring == nil {
		return 0, ErrSealed
	}
	nr := *b.ring
	nr.Keys = append([]barrierKey(nil), b.ring.Keys...)
	term := nr.ActiveTerm + 1
	k := barrierKey{Term: term, Value: randomBytes(32), InstallTime: now()}
	nr.Keys = append(nr.Keys, k)
	nr.ActiveTerm = term
	if err := b.persistKeyring(b.rootKey, &nr); err != nil {
		return 0, err
	}
	a, _ := aeadFor(k.Value)
	b.aeads[term] = a
	b.ring = &nr
	return term, nil
}

// Rekey re-encrypts the keyring under a new root key.
func (b *Barrier) Rekey(newRoot []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ring == nil {
		return ErrSealed
	}
	if err := b.persistKeyring(newRoot, b.ring); err != nil {
		return err
	}
	b.rootKey = append([]byte(nil), newRoot...)
	return nil
}

// VerifyRoot checks a candidate root key without changing state.
func (b *Barrier) VerifyRoot(rootKey []byte) bool {
	ct, ok := b.store.Get(keyringPath)
	if !ok {
		return false
	}
	_, err := openWith(rootKey, []byte(keyringPath), ct)
	return err == nil
}

func (b *Barrier) KeyStatus() (uint32, time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ring == nil {
		return 0, time.Time{}
	}
	for _, k := range b.ring.Keys {
		if k.Term == b.ring.ActiveTerm {
			return k.Term, k.InstallTime
		}
	}
	return b.ring.ActiveTerm, time.Time{}
}

func (b *Barrier) encrypt(path string, pt []byte) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ring == nil {
		return nil, ErrSealed
	}
	term := b.ring.ActiveTerm
	a := b.aeads[term]
	out := make([]byte, 5, 5+a.NonceSize()+len(pt)+a.Overhead())
	out[0] = barrierVersion
	binary.BigEndian.PutUint32(out[1:5], term)
	nonce := randomBytes(a.NonceSize())
	out = append(out, nonce...)
	return a.Seal(out, nonce, pt, []byte(path)), nil
}

func (b *Barrier) decrypt(path string, ct []byte) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ring == nil {
		return nil, ErrSealed
	}
	if len(ct) < 5 || ct[0] != barrierVersion {
		return nil, errors.New("barrier: unknown ciphertext version")
	}
	term := binary.BigEndian.Uint32(ct[1:5])
	a, ok := b.aeads[term]
	if !ok {
		return nil, errors.New("barrier: no key for term")
	}
	ns := a.NonceSize()
	if len(ct) < 5+ns {
		return nil, errors.New("barrier: ciphertext too short")
	}
	return a.Open(nil, ct[5:5+ns], ct[5+ns:], []byte(path))
}

// Get decrypts a value. Missing keys return nil, nil.
func (b *Barrier) Get(path string) ([]byte, error) {
	ct, ok := b.store.Get(barrierPrefix + path)
	if !ok {
		return nil, nil
	}
	return b.decrypt(path, ct)
}

func (b *Barrier) Put(path string, val []byte) error {
	ct, err := b.encrypt(path, val)
	if err != nil {
		return err
	}
	return b.store.Put(barrierPrefix+path, ct)
}

func (b *Barrier) Delete(path string) error { return b.store.Delete(barrierPrefix + path) }

// List returns immediate children (vault semantics).
func (b *Barrier) List(prefix string) ([]string, error) {
	if b.Sealed() {
		return nil, ErrSealed
	}
	return b.store.List(barrierPrefix + prefix), nil
}

// Keys returns all keys under prefix (relative to the barrier root).
func (b *Barrier) Keys(prefix string) []string {
	ks := b.store.Keys(barrierPrefix+prefix, "", 0)
	for i := range ks {
		ks[i] = ks[i][len(barrierPrefix):]
	}
	return ks
}

func (b *Barrier) DeletePrefix(prefix string) error {
	return b.store.DeletePrefix(barrierPrefix + prefix)
}

// View is a prefixed window onto the barrier given to each backend.
type View struct {
	b      *Barrier
	prefix string
}

func (b *Barrier) View(prefix string) *View { return &View{b: b, prefix: prefix} }

func (v *View) Get(k string) ([]byte, error)    { return v.b.Get(v.prefix + k) }
func (v *View) Put(k string, val []byte) error  { return v.b.Put(v.prefix+k, val) }
func (v *View) Delete(k string) error           { return v.b.Delete(v.prefix + k) }
func (v *View) List(p string) ([]string, error) { return v.b.List(v.prefix + p) }
func (v *View) DeletePrefix(p string) error     { return v.b.DeletePrefix(v.prefix + p) }
func (v *View) Keys(p string) []string {
	ks := v.b.Keys(v.prefix + p)
	for i := range ks {
		ks[i] = ks[i][len(v.prefix):]
	}
	return ks
}
func (v *View) Sub(p string) *View { return &View{b: v.b, prefix: v.prefix + p} }

// GetJSON decodes a stored JSON value; returns false if missing.
func (v *View) GetJSON(k string, out any) (bool, error) {
	raw, err := v.Get(k)
	if err != nil || raw == nil {
		return false, err
	}
	return true, json.Unmarshal(raw, out)
}

func (v *View) PutJSON(k string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return v.Put(k, raw)
}
