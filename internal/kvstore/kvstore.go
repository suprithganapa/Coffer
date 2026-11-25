// Package kvstore is a small durable, ordered key/value store used for
// Coffer's secrets storage and filer metadata. Data lives in memory in a
// sorted index and is persisted via an append-only write-ahead log that is
// periodically compacted into a snapshot. Torn writes at the tail of the
// log (e.g. after a crash) are detected by CRC and discarded.
package kvstore

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	opPut byte = 1
	opDel byte = 2

	compactEvery = 20000
)

// Op is a single mutation used with Batch.
type Op struct {
	Key    string
	Value  []byte
	Delete bool
}

// Store is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	data map[string][]byte
	keys []string // sorted
	dir  string
	wal  *os.File
	bw   *bufio.Writer
	ops  int
}

// Open opens (or creates) a store in dir. An empty dir gives an in-memory store.
func Open(dir string) (*Store, error) {
	s := &Store{data: map[string][]byte{}, dir: dir}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := s.loadSnapshot(); err != nil {
		return nil, err
	}
	if err := s.replayWAL(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "wal.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.wal = f
	s.bw = bufio.NewWriter(f)
	s.rebuildKeys()
	return s, nil
}

func (s *Store) rebuildKeys() {
	s.keys = s.keys[:0]
	for k := range s.data {
		s.keys = append(s.keys, k)
	}
	sort.Strings(s.keys)
}

func readRecord(r *bufio.Reader) (op byte, key string, val []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	op = hdr[0]
	kl := binary.BigEndian.Uint32(hdr[1:5])
	vl := binary.BigEndian.Uint32(hdr[5:9])
	if kl > 1<<20 || vl > 1<<30 {
		err = errors.New("corrupt record")
		return
	}
	buf := make([]byte, int(kl)+int(vl)+4)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	body := buf[:kl+vl]
	sum := binary.BigEndian.Uint32(buf[kl+vl:])
	c := crc32.NewIEEE()
	c.Write(hdr[:])
	c.Write(body)
	if c.Sum32() != sum {
		err = errors.New("checksum mismatch")
		return
	}
	key = string(body[:kl])
	val = append([]byte(nil), body[kl:]...)
	return
}

func encodeRecord(op byte, key string, val []byte) []byte {
	buf := make([]byte, 9+len(key)+len(val)+4)
	buf[0] = op
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(key)))
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(val)))
	copy(buf[9:], key)
	copy(buf[9+len(key):], val)
	sum := crc32.ChecksumIEEE(buf[:9+len(key)+len(val)])
	binary.BigEndian.PutUint32(buf[9+len(key)+len(val):], sum)
	return buf
}

func (s *Store) loadSnapshot() error {
	f, err := os.Open(filepath.Join(s.dir, "snapshot.db"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		op, k, v, err := readRecord(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("kvstore: snapshot corrupt: " + err.Error())
		}
		if op == opPut {
			s.data[k] = v
		}
	}
}

func (s *Store) replayWAL() error {
	path := filepath.Join(s.dir, "wal.log")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	r := bufio.NewReader(f)
	var good int64
	for {
		op, k, v, err := readRecord(r)
		if err != nil {
			break // EOF or torn tail
		}
		good += int64(9 + len(k) + len(v) + 4)
		switch op {
		case opPut:
			s.data[k] = v
		case opDel:
			delete(s.data, k)
		}
		s.ops++
	}
	f.Close()
	// drop any torn tail so future appends stay aligned
	return os.Truncate(path, good)
}

func (s *Store) insertKey(k string) {
	i := sort.SearchStrings(s.keys, k)
	if i < len(s.keys) && s.keys[i] == k {
		return
	}
	s.keys = append(s.keys, "")
	copy(s.keys[i+1:], s.keys[i:])
	s.keys[i] = k
}

func (s *Store) removeKey(k string) {
	i := sort.SearchStrings(s.keys, k)
	if i < len(s.keys) && s.keys[i] == k {
		s.keys = append(s.keys[:i], s.keys[i+1:]...)
	}
}

// Get returns a copy of the value, or nil,false.
func (s *Store) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), v...), true
}

// Put stores a value durably.
func (s *Store) Put(key string, val []byte) error {
	return s.Batch([]Op{{Key: key, Value: val}})
}

// Delete removes a key.
func (s *Store) Delete(key string) error {
	return s.Batch([]Op{{Key: key, Delete: true}})
}

// Batch applies all ops atomically with a single fsync.
func (s *Store) Batch(ops []Op) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal != nil {
		for _, o := range ops {
			if o.Delete {
				s.bw.Write(encodeRecord(opDel, o.Key, nil))
			} else {
				s.bw.Write(encodeRecord(opPut, o.Key, o.Value))
			}
		}
		if err := s.bw.Flush(); err != nil {
			return err
		}
		if err := s.wal.Sync(); err != nil {
			return err
		}
	}
	for _, o := range ops {
		if o.Delete {
			if _, ok := s.data[o.Key]; ok {
				delete(s.data, o.Key)
				s.removeKey(o.Key)
			}
		} else {
			if _, ok := s.data[o.Key]; !ok {
				s.insertKey(o.Key)
			}
			s.data[o.Key] = append([]byte(nil), o.Value...)
		}
	}
	s.ops += len(ops)
	if s.wal != nil && s.ops > compactEvery {
		if err := s.compactLocked(); err != nil {
			return err
		}
	}
	return nil
}

// Keys returns all keys with the prefix, sorted, starting after `after`
// (exclusive) and up to limit entries (limit<=0 = unlimited).
func (s *Store) Keys(prefix, after string, limit int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	start := prefix
	if after > start {
		start = after
	}
	i := sort.SearchStrings(s.keys, start)
	var out []string
	for ; i < len(s.keys); i++ {
		k := s.keys[i]
		if !strings.HasPrefix(k, prefix) {
			break
		}
		if k == after {
			continue
		}
		out = append(out, k)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// List returns the immediate children under prefix (vault-style): plain
// names for leaf keys and "name/" for sub-folders.
func (s *Store) List(prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.SearchStrings(s.keys, prefix)
	seen := map[string]bool{}
	var out []string
	for ; i < len(s.keys); i++ {
		k := s.keys[i]
		if !strings.HasPrefix(k, prefix) {
			break
		}
		rest := k[len(prefix):]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j+1]
		}
		if rest != "" && !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

// DeletePrefix removes every key under prefix.
func (s *Store) DeletePrefix(prefix string) error {
	keys := s.Keys(prefix, "", 0)
	ops := make([]Op, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, Op{Key: k, Delete: true})
	}
	if len(ops) == 0 {
		return nil
	}
	return s.Batch(ops)
}

// Len returns number of keys.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

func (s *Store) compactLocked() error {
	tmp := filepath.Join(s.dir, "snapshot.db.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, k := range s.keys {
		w.Write(encodeRecord(opPut, k, s.data[k]))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, filepath.Join(s.dir, "snapshot.db")); err != nil {
		return err
	}
	if err := s.wal.Truncate(0); err != nil {
		return err
	}
	s.wal.Seek(0, io.SeekStart)
	s.bw.Reset(s.wal)
	s.ops = 0
	return nil
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal == nil {
		return nil
	}
	s.bw.Flush()
	err := s.wal.Close()
	s.wal = nil
	return err
}

// Export writes every key/value as snapshot records (consistent point in time).
func (s *Store) Export(w io.Writer) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bw := bufio.NewWriter(w)
	for _, k := range s.keys {
		if _, err := bw.Write(encodeRecord(opPut, k, s.data[k])); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// Restore replaces the store in dir with records from r. The store must not
// be open. The previous contents are kept in dir+".bak-<unix>".
func Restore(dir string, r io.Reader, suffix string) error {
	tmp := dir + ".restore"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(tmp, "snapshot.db"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(f)
	for {
		op, k, v, err := readRecord(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return errors.New("snapshot section is corrupt: " + err.Error())
		}
		bw.Write(encodeRecord(op, k, v))
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	f.Sync()
	f.Close()
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, dir+".bak-"+suffix); err != nil {
			return err
		}
	}
	return os.Rename(tmp, dir)
}
