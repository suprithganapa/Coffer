package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrCookie     = errors.New("cookie mismatch")
	ErrReadOnly   = errors.New("volume is read only")
	ErrVolumeFull = errors.New("volume is full")
	ErrNoSuchVol  = errors.New("volume not found on this server")
	ErrCompacting = errors.New("volume is being compacted")
)

type needleValue struct {
	offset int64 // byte offset in .dat
	length uint32
}

// VolumeInfo is a snapshot of volume state reported to the master.
type VolumeInfo struct {
	ID              uint32 `json:"id"`
	Collection      string `json:"collection"`
	Replication     string `json:"replication"`
	TTLSeconds      uint32 `json:"ttl_seconds"`
	Size            int64  `json:"size"`
	FileCount       int    `json:"file_count"`
	DeleteCount     int    `json:"delete_count"`
	DeletedBytes    int64  `json:"deleted_bytes"`
	ReadOnly        bool   `json:"read_only"`
	CompactRevision uint16 `json:"compact_revision"`
	ModifiedAt      int64  `json:"modified_at"`
}

// Volume is one append-only data file with its index.
type Volume struct {
	mu           sync.RWMutex
	ID           uint32
	Collection   string
	Replication  ReplicaPlacement
	TTLSeconds   uint32
	dir          string
	dat, idx     *os.File
	nm           map[uint64]needleValue
	size         int64
	idxSize      int64
	deleteCount  int
	deletedBytes int64
	readOnly     bool
	revision     uint16
	sizeLimit    int64
	modifiedAt   int64
	compacting   bool
	compactIdxAt int64
}

func volumeBaseName(collection string, id uint32) string {
	if collection == "" {
		return strconv.FormatUint(uint64(id), 10)
	}
	return collection + "_" + strconv.FormatUint(uint64(id), 10)
}

func (v *Volume) base() string { return filepath.Join(v.dir, volumeBaseName(v.Collection, v.ID)) }

// OpenVolume opens or creates a volume.
func OpenVolume(dir, collection string, id uint32, rp ReplicaPlacement, ttl uint32, sizeLimit int64) (*Volume, error) {
	v := &Volume{ID: id, Collection: collection, Replication: rp, TTLSeconds: ttl, dir: dir, sizeLimit: sizeLimit}
	if err := v.load(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Volume) load() error {
	v.nm = map[uint64]needleValue{}
	v.deleteCount, v.deletedBytes = 0, 0
	dat, err := os.OpenFile(v.base()+".dat", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	st, _ := dat.Stat()
	if st.Size() == 0 {
		sb := make([]byte, SuperBlockSize)
		sb[0] = 1
		sb[1] = v.Replication.Byte()
		binary.BigEndian.PutUint16(sb[2:4], v.revision)
		binary.BigEndian.PutUint32(sb[4:8], v.TTLSeconds)
		if _, err := dat.WriteAt(sb, 0); err != nil {
			dat.Close()
			return err
		}
		v.size = SuperBlockSize
	} else {
		sb := make([]byte, SuperBlockSize)
		if _, err := dat.ReadAt(sb, 0); err != nil {
			dat.Close()
			return fmt.Errorf("read superblock: %w", err)
		}
		v.Replication = ReplicationFromByte(sb[1])
		v.revision = binary.BigEndian.Uint16(sb[2:4])
		v.TTLSeconds = binary.BigEndian.Uint32(sb[4:8])
		v.size = st.Size()
		v.modifiedAt = st.ModTime().Unix()
	}
	idx, err := os.OpenFile(v.base()+".idx", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		dat.Close()
		return err
	}
	ist, _ := idx.Stat()
	n := ist.Size() / IdxEntrySize
	if ist.Size()%IdxEntrySize != 0 {
		idx.Truncate(n * IdxEntrySize)
	}
	buf := make([]byte, IdxEntrySize*4096)
	var pos int64
	for pos < n*IdxEntrySize {
		m, err := idx.ReadAt(buf, pos)
		if m == 0 && err != nil {
			break
		}
		m -= m % IdxEntrySize
		for i := 0; i < m; i += IdxEntrySize {
			v.applyIdx(buf[i : i+IdxEntrySize])
		}
		pos += int64(m)
	}
	v.idxSize = n * IdxEntrySize
	v.dat, v.idx = dat, idx
	if v.sizeLimit > 0 && v.size >= v.sizeLimit {
		v.readOnly = true
	}
	return nil
}

func (v *Volume) applyIdx(e []byte) {
	key := binary.BigEndian.Uint64(e[0:8])
	off := int64(binary.BigEndian.Uint32(e[8:12])) * NeedleAlign
	length := binary.BigEndian.Uint32(e[12:16])
	old, had := v.nm[key]
	if length == TombstoneSize {
		if had {
			v.deleteCount++
			v.deletedBytes += int64(old.length)
			delete(v.nm, key)
		}
		return
	}
	if off+int64(length) > v.size {
		return // torn write; data never landed
	}
	if had {
		v.deletedBytes += int64(old.length)
	}
	v.nm[key] = needleValue{offset: off, length: length}
}

func idxEntry(key uint64, off int64, length uint32) []byte {
	e := make([]byte, IdxEntrySize)
	binary.BigEndian.PutUint64(e[0:8], key)
	binary.BigEndian.PutUint32(e[8:12], uint32(off/NeedleAlign))
	binary.BigEndian.PutUint32(e[12:16], length)
	return e
}

// Write appends a needle. Overwriting an existing key requires the same cookie.
func (v *Volume) Write(n *Needle) (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.readOnly {
		return 0, ErrReadOnly
	}
	if old, ok := v.nm[n.ID]; ok {
		hdr := make([]byte, 4)
		if _, err := v.dat.ReadAt(hdr, old.offset); err == nil {
			if binary.BigEndian.Uint32(hdr) != n.Cookie {
				return 0, ErrCookie
			}
		}
	}
	if n.LastModified == 0 {
		n.LastModified = uint64(time.Now().Unix())
	}
	if n.TTLSeconds == 0 {
		n.TTLSeconds = v.TTLSeconds
	}
	b := n.Encode()
	if v.sizeLimit > 0 && v.size+int64(len(b)) > v.sizeLimit && v.size > SuperBlockSize {
		v.readOnly = true
		return 0, ErrVolumeFull
	}
	if v.size/NeedleAlign > 0xFFFFFFFF {
		v.readOnly = true
		return 0, ErrVolumeFull
	}
	off := v.size
	if _, err := v.dat.WriteAt(b, off); err != nil {
		return 0, err
	}
	if _, err := v.idx.WriteAt(idxEntry(n.ID, off, uint32(len(b))), v.idxSize); err != nil {
		return 0, err
	}
	v.idxSize += IdxEntrySize
	v.size += int64(len(b))
	if old, ok := v.nm[n.ID]; ok {
		v.deletedBytes += int64(old.length)
	}
	v.nm[n.ID] = needleValue{offset: off, length: uint32(len(b))}
	v.modifiedAt = time.Now().Unix()
	return uint32(len(n.Data)), nil
}

// Read fetches a needle and verifies the cookie and TTL.
func (v *Volume) Read(key uint64, cookie uint32) (*Needle, error) {
	v.mu.RLock()
	nv, ok := v.nm[key]
	if !ok {
		v.mu.RUnlock()
		return nil, ErrNotFound
	}
	b := make([]byte, nv.length)
	_, err := v.dat.ReadAt(b, nv.offset)
	v.mu.RUnlock()
	if err != nil && err != io.EOF {
		return nil, err
	}
	n, err := DecodeNeedle(b)
	if err != nil {
		return nil, err
	}
	if n.Cookie != cookie {
		return nil, ErrCookie
	}
	if n.TTLSeconds > 0 && int64(n.LastModified)+int64(n.TTLSeconds) < time.Now().Unix() {
		return nil, ErrNotFound
	}
	return n, nil
}

// Delete tombstones a needle. Returns bytes freed.
func (v *Volume) Delete(key uint64, cookie uint32) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	nv, ok := v.nm[key]
	if !ok {
		return 0, ErrNotFound
	}
	hdr := make([]byte, 4)
	if _, err := v.dat.ReadAt(hdr, nv.offset); err != nil {
		return 0, err
	}
	if binary.BigEndian.Uint32(hdr) != cookie {
		return 0, ErrCookie
	}
	if _, err := v.idx.WriteAt(idxEntry(key, 0, TombstoneSize), v.idxSize); err != nil {
		return 0, err
	}
	v.idxSize += IdxEntrySize
	delete(v.nm, key)
	v.deleteCount++
	v.deletedBytes += int64(nv.length)
	v.modifiedAt = time.Now().Unix()
	return int64(nv.length), nil
}

// Info returns a status snapshot.
func (v *Volume) Info() VolumeInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return VolumeInfo{
		ID: v.ID, Collection: v.Collection, Replication: v.Replication.String(),
		TTLSeconds: v.TTLSeconds, Size: v.size, FileCount: len(v.nm),
		DeleteCount: v.deleteCount, DeletedBytes: v.deletedBytes,
		ReadOnly: v.readOnly, CompactRevision: v.revision, ModifiedAt: v.modifiedAt,
	}
}

// GarbageRatio is the fraction of the data file occupied by dead needles.
func (v *Volume) GarbageRatio() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.size <= SuperBlockSize {
		return 0
	}
	return float64(v.deletedBytes) / float64(v.size-SuperBlockSize)
}

func (v *Volume) SetReadOnly(ro bool) {
	v.mu.Lock()
	v.readOnly = ro
	v.mu.Unlock()
}

// Compact rewrites the volume without deleted/expired needles. Writes that
// arrive while copying are replayed from the index before the swap.
func (v *Volume) Compact() error {
	v.mu.Lock()
	if v.compacting {
		v.mu.Unlock()
		return ErrCompacting
	}
	v.compacting = true
	startIdx := v.idxSize
	type ent struct {
		key uint64
		nv  needleValue
	}
	live := make([]ent, 0, len(v.nm))
	for k, nv := range v.nm {
		live = append(live, ent{k, nv})
	}
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		v.compacting = false
		v.mu.Unlock()
	}()
	sort.Slice(live, func(i, j int) bool { return live[i].nv.offset < live[j].nv.offset })

	cpd, err := os.OpenFile(v.base()+".cpd", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	cpx, err := os.OpenFile(v.base()+".cpx", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		cpd.Close()
		return err
	}
	cleanup := func() {
		cpd.Close()
		cpx.Close()
		os.Remove(v.base() + ".cpd")
		os.Remove(v.base() + ".cpx")
	}
	sb := make([]byte, SuperBlockSize)
	sb[0] = 1
	sb[1] = v.Replication.Byte()
	binary.BigEndian.PutUint16(sb[2:4], v.revision+1)
	binary.BigEndian.PutUint32(sb[4:8], v.TTLSeconds)
	cpd.WriteAt(sb, 0)
	newSize := int64(SuperBlockSize)
	var newIdx int64
	now := time.Now().Unix()
	copyOne := func(key uint64, nv needleValue) error {
		b := make([]byte, nv.length)
		v.mu.RLock()
		_, err := v.dat.ReadAt(b, nv.offset)
		v.mu.RUnlock()
		if err != nil && err != io.EOF {
			return err
		}
		n, err := DecodeNeedle(b)
		if err != nil {
			return nil // skip corrupt
		}
		if n.TTLSeconds > 0 && int64(n.LastModified)+int64(n.TTLSeconds) < now {
			return nil
		}
		if _, err := cpd.WriteAt(b, newSize); err != nil {
			return err
		}
		if _, err := cpx.WriteAt(idxEntry(key, newSize, nv.length), newIdx); err != nil {
			return err
		}
		newSize += int64(nv.length)
		newIdx += IdxEntrySize
		return nil
	}
	for _, e := range live {
		if err := copyOne(e.key, e.nv); err != nil {
			cleanup()
			return err
		}
	}

	// Commit: block writers, replay index entries written during the copy.
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.idxSize > startIdx {
		tail := make([]byte, v.idxSize-startIdx)
		v.idx.ReadAt(tail, startIdx)
		for i := 0; i+IdxEntrySize <= len(tail); i += IdxEntrySize {
			e := tail[i : i+IdxEntrySize]
			key := binary.BigEndian.Uint64(e[0:8])
			length := binary.BigEndian.Uint32(e[12:16])
			if length == TombstoneSize {
				cpx.WriteAt(idxEntry(key, 0, TombstoneSize), newIdx)
				newIdx += IdxEntrySize
				continue
			}
			off := int64(binary.BigEndian.Uint32(e[8:12])) * NeedleAlign
			b := make([]byte, length)
			if _, err := v.dat.ReadAt(b, off); err != nil && err != io.EOF {
				cleanup()
				return err
			}
			cpd.WriteAt(b, newSize)
			cpx.WriteAt(idxEntry(key, newSize, length), newIdx)
			newSize += int64(length)
			newIdx += IdxEntrySize
		}
	}
	if err := cpd.Sync(); err != nil {
		cleanup()
		return err
	}
	cpx.Sync()
	cpd.Close()
	cpx.Close()
	v.dat.Close()
	v.idx.Close()
	if err := os.Rename(v.base()+".cpd", v.base()+".dat"); err != nil {
		return err
	}
	if err := os.Rename(v.base()+".cpx", v.base()+".idx"); err != nil {
		return err
	}
	v.readOnly = false
	return v.load()
}

// Close releases file handles.
func (v *Volume) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dat != nil {
		v.dat.Sync()
		v.dat.Close()
		v.idx.Close()
		v.dat, v.idx = nil, nil
	}
}

// Destroy closes and removes the volume files.
func (v *Volume) Destroy() {
	v.Close()
	for _, ext := range []string{".dat", ".idx", ".cpd", ".cpx"} {
		os.Remove(v.base() + ext)
	}
}

// Store is the set of volumes on one volume server.
type Store struct {
	mu         sync.RWMutex
	Dir        string
	MaxVolumes int
	SizeLimit  int64
	volumes    map[uint32]*Volume
}

// OpenStore loads all volumes found in dir.
func OpenStore(dir string, maxVolumes int, sizeLimit int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, MaxVolumes: maxVolumes, SizeLimit: sizeLimit, volumes: map[uint32]*Volume{}}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.dat"))
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".dat")
		coll := ""
		idPart := name
		if i := strings.LastIndexByte(name, '_'); i >= 0 {
			coll, idPart = name[:i], name[i+1:]
		}
		id, err := strconv.ParseUint(idPart, 10, 32)
		if err != nil {
			continue
		}
		v, err := OpenVolume(dir, coll, uint32(id), ReplicaPlacement{}, 0, sizeLimit)
		if err != nil {
			return nil, fmt.Errorf("open volume %s: %w", name, err)
		}
		s.volumes[uint32(id)] = v
	}
	return s, nil
}

// SetSizeLimit updates the limit applied to newly created volumes.
func (s *Store) SetSizeLimit(n int64) {
	s.mu.Lock()
	s.SizeLimit = n
	s.mu.Unlock()
}

func (s *Store) Get(id uint32) *Volume {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.volumes[id]
}

// AddVolume creates a volume if it doesn't exist.
func (s *Store) AddVolume(id uint32, collection string, rp ReplicaPlacement, ttl uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.volumes[id]; ok {
		return nil
	}
	if len(s.volumes) >= s.MaxVolumes {
		return errors.New("no free volume slots")
	}
	v, err := OpenVolume(s.Dir, collection, id, rp, ttl, s.SizeLimit)
	if err != nil {
		return err
	}
	s.volumes[id] = v
	return nil
}

func (s *Store) DeleteVolume(id uint32) error {
	s.mu.Lock()
	v, ok := s.volumes[id]
	delete(s.volumes, id)
	s.mu.Unlock()
	if !ok {
		return ErrNoSuchVol
	}
	v.Destroy()
	return nil
}

func (s *Store) Infos() []VolumeInfo {
	s.mu.RLock()
	vs := make([]*Volume, 0, len(s.volumes))
	for _, v := range s.volumes {
		vs = append(vs, v)
	}
	s.mu.RUnlock()
	out := make([]VolumeInfo, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.volumes {
		v.Close()
	}
}
