// Package filer provides a POSIX-like namespace (directories, files, metadata)
// on top of Coffer's blob storage. Large files are split into chunks stored
// on volume servers. Folders can carry settings inherited by everything
// below them: an encryption key (envelope encryption through the transit
// engine), a replication level and a TTL.
package filer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"coffer/internal/kvstore"
	"coffer/internal/storage"
)

var (
	ErrNotFound     = errors.New("no such file or directory")
	ErrExists       = errors.New("already exists")
	ErrNotDir       = errors.New("not a directory")
	ErrIsDir        = errors.New("is a directory")
	ErrNotEmpty     = errors.New("directory not empty")
	ErrInvalidPath  = errors.New("invalid path")
	ErrRootReadOnly = errors.New("cannot modify the root directory")
)

const BucketsDir = "/buckets"

// Chunk is one piece of a file stored as a blob.
type Chunk struct {
	Fid        string `json:"fid"`
	Offset     int64  `json:"offset"`
	Size       int64  `json:"size"`
	ETag       string `json:"etag,omitempty"`
	KeyName    string `json:"key_name,omitempty"`    // transit key protecting this chunk
	WrappedKey string `json:"wrapped_key,omitempty"` // wrapped data key
}

// DirConfig is inherited by descendants of a folder.
type DirConfig struct {
	EncryptionKey string `json:"encryption_key,omitempty"`
	Replication   string `json:"replication,omitempty"`
	TTL           string `json:"ttl,omitempty"`
}

// Entry is a file or directory.
type Entry struct {
	Dir      string            `json:"dir"`
	Name     string            `json:"name"`
	IsDir    bool              `json:"is_dir"`
	Mode     uint32            `json:"mode"`
	Mtime    time.Time         `json:"mtime"`
	Crtime   time.Time         `json:"crtime"`
	Mime     string            `json:"mime,omitempty"`
	Size     int64             `json:"size"`
	MD5      string            `json:"md5,omitempty"`
	ETag     string            `json:"etag,omitempty"`
	Chunks   []Chunk           `json:"chunks,omitempty"`
	TTL      string            `json:"ttl,omitempty"`
	Extended map[string]string `json:"extended,omitempty"`
	Config   *DirConfig        `json:"config,omitempty"`
	Owner    string            `json:"owner,omitempty"`
}

func (e *Entry) FullPath() string {
	if e.Dir == "/" {
		return "/" + e.Name
	}
	return e.Dir + "/" + e.Name
}

// Encrypted reports whether any chunk is encrypted.
func (e *Entry) Encrypted() bool {
	for _, c := range e.Chunks {
		if c.WrappedKey != "" {
			return true
		}
	}
	return false
}

// Expired reports whether a TTL'd file has lapsed.
func (e *Entry) Expired() bool {
	if e.TTL == "" || e.IsDir {
		return false
	}
	secs, err := storage.ParseTTL(e.TTL)
	if err != nil || secs == 0 {
		return false
	}
	return time.Since(e.Mtime) > time.Duration(secs)*time.Second
}

// KeyService provides envelope encryption (implemented by the vault core).
type KeyService interface {
	EnsureTransitKey(name string) error
	GenerateDataKey(keyName string, context []byte) ([]byte, string, error)
	UnwrapDataKey(keyName, wrapped string, context []byte) ([]byte, error)
}

// Filer is the namespace service.
type Filer struct {
	store      *kvstore.Store
	Client     *storage.Client
	Keys       KeyService
	ChunkSize  int64
	DefaultRep string
	mu         sync.Mutex

	dekMu    sync.Mutex
	dekCache map[string][]byte
	delQ     chan []string
}

// New creates a filer over a metadata store and blob client.
func New(store *kvstore.Store, client *storage.Client, keys KeyService) *Filer {
	f := &Filer{store: store, Client: client, Keys: keys, ChunkSize: 4 << 20, dekCache: map[string][]byte{}, delQ: make(chan []string, 1024)}
	go f.deleteLoop()
	return f
}

// ForgetKeys wipes cached data keys (called when the core seals).
func (f *Filer) ForgetKeys() {
	f.dekMu.Lock()
	for k, v := range f.dekCache {
		for i := range v {
			v[i] = 0
		}
		delete(f.dekCache, k)
	}
	f.dekMu.Unlock()
}

// Clean normalizes a path to "/a/b" form.
func Clean(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", ErrInvalidPath
	}
	p = path.Clean("/" + p)
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 255 {
			return "", ErrInvalidPath
		}
	}
	return p, nil
}

func split(p string) (dir, name string) {
	dir, name = path.Split(p)
	if dir != "/" {
		dir = strings.TrimSuffix(dir, "/")
	}
	return
}

func entryKey(dir, name string) string { return "e:" + dir + "\x00" + name }

func dirPrefix(dir string) string { return "e:" + dir + "\x00" }

func (f *Filer) get(dir, name string) (*Entry, error) {
	raw, ok := f.store.Get(entryKey(dir, name))
	if !ok {
		return nil, ErrNotFound
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func rootEntry() *Entry {
	return &Entry{Dir: "", Name: "", IsDir: true, Mode: 0o755}
}

// Find returns the entry at path.
func (f *Filer) Find(p string) (*Entry, error) {
	p, err := Clean(p)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return rootEntry(), nil
	}
	d, n := split(p)
	e, err := f.get(d, n)
	if err != nil {
		return nil, err
	}
	if e.Expired() {
		go f.Delete(p, false)
		return nil, ErrNotFound
	}
	return e, nil
}

func (f *Filer) putLocked(e *Entry) error {
	raw, _ := json.Marshal(e)
	return f.store.Put(entryKey(e.Dir, e.Name), raw)
}

// mkdirAllLocked ensures every directory in p exists.
func (f *Filer) mkdirAllLocked(p, owner string) error {
	if p == "/" {
		return nil
	}
	cur := ""
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		parent := cur
		if parent == "" {
			parent = "/"
		}
		cur += "/" + seg
		e, err := f.get(parent, seg)
		if err == nil {
			if !e.IsDir {
				return fmt.Errorf("%s: %w", cur, ErrNotDir)
			}
			continue
		}
		t := time.Now().UTC()
		if err := f.putLocked(&Entry{Dir: parent, Name: seg, IsDir: true, Mode: 0o755, Mtime: t, Crtime: t, Owner: owner}); err != nil {
			return err
		}
	}
	return nil
}

// Mkdir creates a directory (and parents).
func (f *Filer) Mkdir(p, owner string) (*Entry, error) {
	p, err := Clean(p)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return rootEntry(), nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, n := split(p)
	if e, err := f.get(d, n); err == nil {
		if e.IsDir {
			return e, nil
		}
		return nil, fmt.Errorf("%s: %w", p, ErrExists)
	}
	if err := f.mkdirAllLocked(p, owner); err != nil {
		return nil, err
	}
	return f.get(d, n)
}

// ListOptions controls directory listings.
type ListOptions struct {
	StartAfter string // name to start after (exclusive)
	Prefix     string // name prefix
	Limit      int
	ShowHidden bool
}

// List returns children of a directory sorted by name.
func (f *Filer) List(dir string, o ListOptions) ([]*Entry, bool, error) {
	dir, err := Clean(dir)
	if err != nil {
		return nil, false, err
	}
	if dir != "/" {
		e, err := f.Find(dir)
		if err != nil {
			return nil, false, err
		}
		if !e.IsDir {
			return nil, false, ErrNotDir
		}
	}
	prefix := dirPrefix(dir)
	after := ""
	if o.StartAfter != "" {
		after = prefix + o.StartAfter
	}
	if o.Prefix != "" && prefix+o.Prefix > after {
		after = ""
	}
	limit := o.Limit
	if limit <= 0 {
		limit = 10000
	}
	var out []*Entry
	more := false
	scanFrom := after
	for {
		batch := f.store.Keys(prefix+o.Prefix, scanFrom, limit+1)
		if len(batch) == 0 {
			break
		}
		for _, k := range batch {
			scanFrom = k
			raw, ok := f.store.Get(k)
			if !ok {
				continue
			}
			var e Entry
			if json.Unmarshal(raw, &e) != nil {
				continue
			}
			if !o.ShowHidden && strings.HasPrefix(e.Name, ".uploads") && dirIsBucket(dir) {
				continue
			}
			if e.Expired() {
				continue
			}
			if len(out) >= limit {
				more = true
				break
			}
			out = append(out, &e)
		}
		if more || len(batch) < limit+1 {
			break
		}
	}
	return out, more, nil
}

func dirIsBucket(dir string) bool {
	return strings.HasPrefix(dir, BucketsDir+"/") && strings.Count(dir, "/") == 2
}

// BucketOf returns the bucket name for a path under /buckets, or "".
func BucketOf(p string) string {
	if !strings.HasPrefix(p, BucketsDir+"/") {
		return ""
	}
	rest := strings.TrimPrefix(p, BucketsDir+"/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// EffectiveConfig merges DirConfig from the root down to dir.
func (f *Filer) EffectiveConfig(dir string) DirConfig {
	var cfg DirConfig
	if dir == "/" || dir == "" {
		return cfg
	}
	cur := ""
	for _, seg := range strings.Split(strings.Trim(dir, "/"), "/") {
		parent := cur
		if parent == "" {
			parent = "/"
		}
		cur += "/" + seg
		e, err := f.get(parent, seg)
		if err != nil || e.Config == nil {
			continue
		}
		if e.Config.EncryptionKey != "" {
			cfg.EncryptionKey = e.Config.EncryptionKey
		}
		if e.Config.EncryptionKey == "-" {
			cfg.EncryptionKey = ""
		}
		if e.Config.Replication != "" {
			cfg.Replication = e.Config.Replication
		}
		if e.Config.TTL != "" {
			cfg.TTL = e.Config.TTL
		}
	}
	return cfg
}

// SetDirConfig updates a folder's inherited settings.
func (f *Filer) SetDirConfig(p string, cfg DirConfig) (*Entry, error) {
	p, err := Clean(p)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return nil, ErrRootReadOnly
	}
	if cfg.Replication != "" {
		if _, err := storage.ParseReplication(cfg.Replication); err != nil {
			return nil, err
		}
	}
	if cfg.TTL != "" {
		if _, err := storage.ParseTTL(cfg.TTL); err != nil {
			return nil, err
		}
	}
	if cfg.EncryptionKey != "" && cfg.EncryptionKey != "-" {
		if err := f.Keys.EnsureTransitKey(cfg.EncryptionKey); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, n := split(p)
	e, err := f.get(d, n)
	if err != nil {
		return nil, err
	}
	if !e.IsDir {
		return nil, ErrNotDir
	}
	if cfg == (DirConfig{}) {
		e.Config = nil
	} else {
		e.Config = &cfg
	}
	e.Mtime = time.Now().UTC()
	return e, f.putLocked(e)
}

// WriteOptions for WriteFile.
type WriteOptions struct {
	Mime     string
	TTL      string
	Extended map[string]string
	Owner    string
	// IfMatch/IfNoneMatch semantics are handled by callers.
}

func (f *Filer) dataKey(keyName string) ([]byte, string, error) {
	plain, wrapped, err := f.Keys.GenerateDataKey(keyName, nil)
	if err != nil {
		return nil, "", err
	}
	f.dekMu.Lock()
	if len(f.dekCache) > 4096 {
		f.dekCache = map[string][]byte{}
	}
	f.dekCache[wrapped] = append([]byte(nil), plain...)
	f.dekMu.Unlock()
	return plain, wrapped, nil
}

func (f *Filer) unwrap(keyName, wrapped string) ([]byte, error) {
	f.dekMu.Lock()
	if k, ok := f.dekCache[wrapped]; ok {
		f.dekMu.Unlock()
		return k, nil
	}
	f.dekMu.Unlock()
	k, err := f.Keys.UnwrapDataKey(keyName, wrapped, nil)
	if err != nil {
		return nil, err
	}
	f.dekMu.Lock()
	if len(f.dekCache) > 4096 {
		f.dekCache = map[string][]byte{}
	}
	f.dekCache[wrapped] = k
	f.dekMu.Unlock()
	return k, nil
}

func sealChunk(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return g.Seal(nonce, nonce, data, nil), nil
}

func openChunk(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < g.NonceSize() {
		return nil, errors.New("encrypted chunk too short")
	}
	return g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], nil)
}

// UploadChunks streams r into chunks; returns chunks, size and md5.
func (f *Filer) UploadChunks(r io.Reader, dir, name, mime string, cfg DirConfig) ([]Chunk, int64, string, error) {
	collection := BucketOf(path.Join(dir, name))
	repl := cfg.Replication
	if repl == "" {
		repl = f.DefaultRep
	}
	var key []byte
	var wrapped string
	if cfg.EncryptionKey != "" {
		var err error
		key, wrapped, err = f.dataKey(cfg.EncryptionKey)
		if err != nil {
			return nil, 0, "", fmt.Errorf("encryption key %q unavailable: %w", cfg.EncryptionKey, err)
		}
	}
	h := md5.New()
	buf := make([]byte, f.ChunkSize)
	var chunks []Chunk
	var off int64
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			data := buf[:n]
			h.Write(data)
			ch := md5.Sum(data)
			payload := data
			blobName, blobMime := name, mime
			if key != nil {
				payload, err = sealChunk(key, data)
				if err != nil {
					f.deleteChunks(chunks)
					return nil, 0, "", err
				}
				blobName, blobMime = "", "application/octet-stream" // don't leak names
			}
			fid, uerr := f.Client.Upload(payload, blobName, blobMime, collection, repl, cfg.TTL)
			if uerr != nil {
				f.deleteChunks(chunks)
				return nil, 0, "", uerr
			}
			c := Chunk{Fid: fid, Offset: off, Size: int64(n), ETag: hex.EncodeToString(ch[:])}
			if key != nil {
				c.KeyName, c.WrappedKey = cfg.EncryptionKey, wrapped
			}
			chunks = append(chunks, c)
			off += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			f.deleteChunks(chunks)
			return nil, 0, "", err
		}
	}
	return chunks, off, hex.EncodeToString(h.Sum(nil)), nil
}

// WriteFile stores r at path, replacing any existing file.
func (f *Filer) WriteFile(p string, r io.Reader, o WriteOptions) (*Entry, error) {
	p, err := Clean(p)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return nil, ErrRootReadOnly
	}
	d, n := split(p)
	if existing, err := f.get(d, n); err == nil && existing.IsDir {
		return nil, ErrIsDir
	}
	if o.Mime == "" || o.Mime == "application/x-www-form-urlencoded" || o.Mime == "application/octet-stream" {
		if m := mimeByExt(n); m != "" {
			o.Mime = m
		}
	}
	cfg := f.EffectiveConfig(d)
	if o.TTL != "" {
		if _, err := storage.ParseTTL(o.TTL); err != nil {
			return nil, err
		}
		cfg.TTL = o.TTL
	}
	chunks, size, sum, err := f.UploadChunks(r, d, n, o.Mime, cfg)
	if err != nil {
		return nil, err
	}
	t := time.Now().UTC()
	e := &Entry{Dir: d, Name: n, Mode: 0o644, Mtime: t, Crtime: t, Mime: o.Mime, Size: size, MD5: sum, ETag: sum, Chunks: chunks, TTL: cfg.TTL, Extended: o.Extended, Owner: o.Owner}
	if err := f.Save(e); err != nil {
		f.deleteChunks(chunks)
		return nil, err
	}
	return e, nil
}

// Save persists an entry (creating parents), replacing any existing file
// and garbage-collecting chunks the old version no longer shares.
func (f *Filer) Save(e *Entry) error {
	f.mu.Lock()
	if err := f.mkdirAllLocked(e.Dir, e.Owner); err != nil {
		f.mu.Unlock()
		return err
	}
	old, err := f.get(e.Dir, e.Name)
	if err == nil {
		if old.IsDir != e.IsDir {
			f.mu.Unlock()
			if old.IsDir {
				return ErrIsDir
			}
			return ErrNotDir
		}
		if !e.Crtime.IsZero() && !old.Crtime.IsZero() {
			e.Crtime = old.Crtime
		}
	}
	if err := f.putLocked(e); err != nil {
		f.mu.Unlock()
		return err
	}
	f.mu.Unlock()
	if old != nil && !old.IsDir {
		keep := map[string]bool{}
		for _, c := range e.Chunks {
			keep[c.Fid] = true
		}
		var gone []Chunk
		for _, c := range old.Chunks {
			if !keep[c.Fid] {
				gone = append(gone, c)
			}
		}
		f.deleteChunks(gone)
	}
	return nil
}

// UpdateMeta rewrites an entry's metadata without touching data.
func (f *Filer) UpdateMeta(e *Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.get(e.Dir, e.Name); err != nil {
		return err
	}
	return f.putLocked(e)
}

func (f *Filer) deleteChunks(chunks []Chunk) {
	if len(chunks) == 0 {
		return
	}
	fids := make([]string, len(chunks))
	for i, c := range chunks {
		fids[i] = c.Fid
	}
	select {
	case f.delQ <- fids:
	default:
		go f.deleteFids(fids)
	}
}

func (f *Filer) deleteLoop() {
	for fids := range f.delQ {
		f.deleteFids(fids)
	}
}

func (f *Filer) deleteFids(fids []string) {
	for _, fid := range fids {
		var err error
		for i := 0; i < 3; i++ {
			if err = f.Client.Delete(fid); err == nil {
				break
			}
			time.Sleep(time.Duration(i+1) * 300 * time.Millisecond)
		}
		if err != nil {
			log.Printf("filer: failed to delete chunk %s: %v", fid, err)
		}
	}
}

// Delete removes a file or directory. Directories need recursive=true unless empty.
func (f *Filer) Delete(p string, recursive bool) error {
	return f.delete(p, recursive, true)
}

// DeleteMetaOnly removes the entry but keeps its chunks (used when chunks
// were adopted by another entry, e.g. multipart completion).
func (f *Filer) DeleteMetaOnly(p string, recursive bool) error {
	return f.delete(p, recursive, false)
}

func (f *Filer) delete(p string, recursive, chunks bool) error {
	p, err := Clean(p)
	if err != nil {
		return err
	}
	if p == "/" {
		return ErrRootReadOnly
	}
	f.mu.Lock()
	d, n := split(p)
	e, err := f.get(d, n)
	if err != nil {
		f.mu.Unlock()
		return err
	}
	var victims []Chunk
	var ops []kvstore.Op
	if e.IsDir {
		children := f.store.Keys(dirPrefix(p), "", 1)
		if len(children) > 0 && !recursive {
			f.mu.Unlock()
			return ErrNotEmpty
		}
		f.walkLocked(p, func(k string, ce *Entry) {
			ops = append(ops, kvstore.Op{Key: k, Delete: true})
			if !ce.IsDir {
				victims = append(victims, ce.Chunks...)
			}
		})
	} else {
		victims = e.Chunks
	}
	ops = append(ops, kvstore.Op{Key: entryKey(d, n), Delete: true})
	err = f.store.Batch(ops)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if chunks {
		f.deleteChunks(victims)
	}
	return nil
}

// walkLocked visits every descendant of dir (depth-first).
func (f *Filer) walkLocked(dir string, fn func(key string, e *Entry)) {
	for _, k := range f.store.Keys(dirPrefix(dir), "", 0) {
		raw, ok := f.store.Get(k)
		if !ok {
			continue
		}
		var e Entry
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		if e.IsDir {
			f.walkLocked(e.FullPath(), fn)
		}
		fn(k, &e)
	}
}

// Walk visits all descendants (read-only snapshot).
func (f *Filer) Walk(dir string, fn func(e *Entry)) {
	f.mu.Lock()
	var all []*Entry
	f.walkLocked(dir, func(_ string, e *Entry) { all = append(all, e) })
	f.mu.Unlock()
	for _, e := range all {
		fn(e)
	}
}

// Rename moves a file or directory (metadata only — no data copy).
func (f *Filer) Rename(from, to string, overwrite bool) (*Entry, error) {
	from, err := Clean(from)
	if err != nil {
		return nil, err
	}
	to, err = Clean(to)
	if err != nil {
		return nil, err
	}
	if from == "/" || to == "/" {
		return nil, ErrRootReadOnly
	}
	if from == to {
		return f.Find(from)
	}
	if strings.HasPrefix(to, from+"/") {
		return nil, errors.New("cannot move a directory into itself")
	}
	f.mu.Lock()
	fd, fn := split(from)
	src, err := f.get(fd, fn)
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	td, tn := split(to)
	var replaced *Entry
	if dst, err := f.get(td, tn); err == nil {
		if !overwrite || dst.IsDir || src.IsDir {
			f.mu.Unlock()
			return nil, fmt.Errorf("%s: %w", to, ErrExists)
		}
		replaced = dst
	}
	if err := f.mkdirAllLocked(td, src.Owner); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	var ops []kvstore.Op
	if src.IsDir {
		f.walkLocked(from, func(k string, ce *Entry) {
			ops = append(ops, kvstore.Op{Key: k, Delete: true})
			ce.Dir = to + strings.TrimPrefix(ce.Dir, from)
			raw, _ := json.Marshal(ce)
			ops = append(ops, kvstore.Op{Key: entryKey(ce.Dir, ce.Name), Value: raw})
		})
	}
	ops = append(ops, kvstore.Op{Key: entryKey(fd, fn), Delete: true})
	src.Dir, src.Name = td, tn
	src.Mtime = time.Now().UTC()
	raw, _ := json.Marshal(src)
	ops = append(ops, kvstore.Op{Key: entryKey(td, tn), Value: raw})
	// deletes must not clobber freshly written keys: apply deletes first
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].Delete && !ops[j].Delete })
	err = f.store.Batch(ops)
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if replaced != nil {
		f.deleteChunks(replaced.Chunks)
	}
	return src, nil
}

// Copy duplicates a file's data into a new entry (new chunks, re-encrypted
// according to the destination folder's settings).
func (f *Filer) Copy(from, to string, o WriteOptions) (*Entry, error) {
	src, err := f.Find(from)
	if err != nil {
		return nil, err
	}
	if src.IsDir {
		return nil, ErrIsDir
	}
	r := f.NewReader(src)
	if o.Mime == "" {
		o.Mime = src.Mime
	}
	if o.Extended == nil {
		o.Extended = src.Extended
	}
	return f.WriteFile(to, r, o)
}

// ---------------- reading ----------------

// Reader is an io.ReadSeeker over a file's chunks.
type Reader struct {
	f      *Filer
	e      *Entry
	pos    int64
	cIdx   int
	cData  []byte
	loaded bool
}

func (f *Filer) NewReader(e *Entry) *Reader { return &Reader{f: f, e: e, cIdx: -1} }

func (f *Filer) fetchChunk(c Chunk) ([]byte, error) {
	data, err := f.Client.Fetch(c.Fid)
	if err != nil {
		return nil, err
	}
	if c.WrappedKey != "" {
		key, err := f.unwrap(c.KeyName, c.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt (is Coffer unsealed and is key %q available?): %w", c.KeyName, err)
		}
		if data, err = openChunk(key, data); err != nil {
			return nil, fmt.Errorf("chunk %s failed integrity check: %w", c.Fid, err)
		}
	}
	if int64(len(data)) != c.Size {
		return nil, fmt.Errorf("chunk %s has wrong size %d (want %d)", c.Fid, len(data), c.Size)
	}
	return data, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.pos >= r.e.Size {
		return 0, io.EOF
	}
	idx := sort.Search(len(r.e.Chunks), func(i int) bool {
		c := r.e.Chunks[i]
		return c.Offset+c.Size > r.pos
	})
	if idx >= len(r.e.Chunks) {
		return 0, io.EOF
	}
	c := r.e.Chunks[idx]
	if r.pos < c.Offset { // sparse region
		n := int(min(int64(len(p)), c.Offset-r.pos))
		clear(p[:n])
		r.pos += int64(n)
		return n, nil
	}
	if r.cIdx != idx {
		data, err := r.f.fetchChunk(c)
		if err != nil {
			return 0, err
		}
		r.cIdx, r.cData = idx, data
	}
	n := copy(p, r.cData[r.pos-c.Offset:])
	r.pos += int64(n)
	return n, nil
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var np int64
	switch whence {
	case io.SeekStart:
		np = offset
	case io.SeekCurrent:
		np = r.pos + offset
	case io.SeekEnd:
		np = r.e.Size + offset
	}
	if np < 0 {
		return 0, errors.New("negative position")
	}
	r.pos = np
	return np, nil
}

// ReadAll loads a whole (small) file.
func (f *Filer) ReadAll(e *Entry) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, f.NewReader(e))
	return buf.Bytes(), err
}

// ---------------- buckets ----------------

// DeleteBucket removes a bucket. Non-empty buckets need force=true.
func (f *Filer) DeleteBucket(name string, force bool) error {
	p := BucketsDir + "/" + name
	e, err := f.Find(p)
	if err != nil {
		return err
	}
	if !e.IsDir {
		return ErrNotDir
	}
	if !force {
		items, _, err := f.List(p, ListOptions{Limit: 1})
		if err != nil {
			return err
		}
		if len(items) > 0 {
			return ErrNotEmpty
		}
	}
	// Drop metadata without per-chunk deletes, then drop the whole collection.
	if err := f.DeleteMetaOnly(p, true); err != nil {
		return err
	}
	if err := f.Client.Call("/col/delete?collection="+name, nil); err != nil {
		log.Printf("filer: delete collection %s: %v", name, err)
	}
	return nil
}

// Stats summarizes the namespace.
type Stats struct {
	Files     int64 `json:"files"`
	Dirs      int64 `json:"dirs"`
	Bytes     int64 `json:"bytes"`
	Encrypted int64 `json:"encrypted_files"`
	Buckets   int64 `json:"buckets"`
}

func (f *Filer) Stats() Stats {
	var s Stats
	f.Walk("/", func(e *Entry) {
		if e.IsDir {
			s.Dirs++
			if e.Dir == BucketsDir {
				s.Buckets++
			}
			return
		}
		s.Files++
		s.Bytes += e.Size
		if e.Encrypted() {
			s.Encrypted++
		}
	})
	return s
}

// SweepExpired deletes TTL-expired files.
func (f *Filer) SweepExpired() int {
	var victims []string
	f.Walk("/", func(e *Entry) {
		if e.Expired() {
			victims = append(victims, e.FullPath())
		}
	})
	for _, v := range victims {
		f.Delete(v, false)
	}
	return len(victims)
}

func mimeByExt(name string) string { return mime.TypeByExtension(path.Ext(name)) }

// DeleteChunksAsync frees blobs in the background.
func (f *Filer) DeleteChunksAsync(chunks []Chunk) { f.deleteChunks(chunks) }
