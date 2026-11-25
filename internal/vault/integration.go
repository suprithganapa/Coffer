package vault

import (
	"strconv"
	"time"
)

// This file exposes core capabilities to the other Coffer subsystems
// (filer, S3 gateway) so storage encryption and access control share the
// same keys, policies and audit trail as the secrets engines.

// TransitMount is where the filer finds encryption keys.
const TransitMount = "transit/"

func (c *Core) transit() (*transitBackend, error) {
	c.mountsMu.RLock()
	defer c.mountsMu.RUnlock()
	m, ok := c.mounts[TransitMount]
	if !ok {
		return nil, badRequest("transit engine is not mounted at %s", TransitMount)
	}
	tb, ok := m.backend.(*transitBackend)
	if !ok {
		return nil, badRequest("mount %s is not a transit engine", TransitMount)
	}
	return tb, nil
}

// EnsureTransitKey creates an AES-256-GCM key if missing.
func (c *Core) EnsureTransitKey(name string) error {
	if c.Sealed() {
		return ErrSealed
	}
	tb, err := c.transit()
	if err != nil {
		return err
	}
	k, err := tb.CreateKey(name, "aes256-gcm96")
	if err != nil {
		return err
	}
	if !k.supportsEncryption() {
		return badRequest("transit key %q (type %s) cannot encrypt data", name, k.Type)
	}
	return nil
}

// GenerateDataKey returns a fresh 256-bit data key and its wrapped form.
func (c *Core) GenerateDataKey(keyName string, context []byte) ([]byte, string, error) {
	if c.Sealed() {
		return nil, "", ErrSealed
	}
	tb, err := c.transit()
	if err != nil {
		return nil, "", err
	}
	return tb.GenerateDataKey(keyName, context)
}

// UnwrapDataKey decrypts a wrapped data key.
func (c *Core) UnwrapDataKey(keyName, wrapped string, context []byte) ([]byte, error) {
	if c.Sealed() {
		return nil, ErrSealed
	}
	tb, err := c.transit()
	if err != nil {
		return nil, err
	}
	return tb.UnwrapDataKey(keyName, wrapped, context)
}

// SysView exposes a barrier view under sys/<sub> for subsystem state
// (S3 credentials, share links). Data is encrypted like everything else.
func (c *Core) SysView(sub string) *View { return c.barrier.View("sys/ext/" + sub) }

// autoRotate rotates transit keys whose auto_rotate_period elapsed.
func (b *transitBackend) autoRotate() {
	keys, err := b.view.List("policy/")
	if err != nil {
		return
	}
	for _, name := range keys {
		k, err := b.getKey(name)
		if err != nil || k == nil || k.AutoRotatePeriod <= 0 {
			continue
		}
		latest := k.Versions[strconv.Itoa(k.LatestVersion)]
		if time.Since(latest.CreationTime) >= k.AutoRotatePeriod {
			b.rotate(name)
		}
	}
}

func (c *Core) runAutoRotate() {
	c.mountsMu.RLock()
	var tbs []*transitBackend
	for _, m := range c.mounts {
		if tb, ok := m.backend.(*transitBackend); ok {
			tbs = append(tbs, tb)
		}
	}
	c.mountsMu.RUnlock()
	for _, tb := range tbs {
		tb.autoRotate()
	}
}
