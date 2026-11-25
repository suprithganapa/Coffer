package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func urlq(s string) string { return url.QueryEscape(s) }

// VolumeServer serves blobs and replicates writes to peers.
type VolumeServer struct {
	Store        *Store
	URL          string // host:port others use to reach us
	PublicURL    string
	Masters      []string
	DataCenter   string
	Rack         string
	Auth         *ClusterAuth
	MaxUploadMB  int64
	client       *http.Client
	lookupMu     sync.Mutex
	lookupCache  map[uint32]lookupEntry
	masterMu     sync.Mutex
	activeMaster int
}

type lookupEntry struct {
	locs []Location
	at   time.Time
}

func NewVolumeServer(store *Store, url, publicURL string, masters []string, dc, rack string, auth *ClusterAuth) *VolumeServer {
	if publicURL == "" {
		publicURL = url
	}
	return &VolumeServer{
		Store: store, URL: url, PublicURL: publicURL, Masters: masters, DataCenter: dc, Rack: rack,
		Auth: auth, MaxUploadMB: 256, client: &http.Client{Timeout: 120 * time.Second},
		lookupCache: map[uint32]lookupEntry{},
	}
}

func (vs *VolumeServer) master() string {
	vs.masterMu.Lock()
	defer vs.masterMu.Unlock()
	return vs.Masters[vs.activeMaster%len(vs.Masters)]
}

func (vs *VolumeServer) rotateMaster() {
	vs.masterMu.Lock()
	vs.activeMaster++
	vs.masterMu.Unlock()
}

// Heartbeat sends our state to the master once.
func (vs *VolumeServer) Heartbeat() error {
	hb := Heartbeat{URL: vs.URL, PublicURL: vs.PublicURL, DataCenter: vs.DataCenter, Rack: vs.Rack, MaxVolumes: vs.Store.MaxVolumes, Volumes: vs.Store.Infos()}
	b, _ := json.Marshal(hb)
	req, _ := http.NewRequest(http.MethodPost, "http://"+vs.master()+"/dir/heartbeat", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	vs.Auth.SetAuth(req, AdminScope)
	resp, err := vs.client.Do(req)
	if err != nil {
		vs.rotateMaster()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("heartbeat rejected: %d", resp.StatusCode)
	}
	var r struct {
		VolumeSizeLimit int64 `json:"volume_size_limit"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) == nil && r.VolumeSizeLimit > 0 {
		vs.Store.SetSizeLimit(r.VolumeSizeLimit)
	}
	return nil
}

// RunHeartbeat loops until stop is closed.
func (vs *VolumeServer) RunHeartbeat(stop <-chan struct{}) {
	failing := false
	for {
		if err := vs.Heartbeat(); err != nil {
			if !failing {
				log.Printf("volume %s: heartbeat to master failed: %v", vs.URL, err)
			}
			failing = true
		} else if failing {
			log.Printf("volume %s: reconnected to master", vs.URL)
			failing = false
		}
		select {
		case <-stop:
			return
		case <-time.After(HeartbeatInterval):
		}
	}
}

func (vs *VolumeServer) lookup(vid uint32) ([]Location, error) {
	vs.lookupMu.Lock()
	if e, ok := vs.lookupCache[vid]; ok && time.Since(e.at) < 10*time.Second {
		vs.lookupMu.Unlock()
		return e.locs, nil
	}
	vs.lookupMu.Unlock()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/dir/lookup?volumeId=%d", vs.master(), vid), nil)
	vs.Auth.SetAuth(req, AdminScope)
	resp, err := vs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Locations []Location `json:"locations"`
		Error     string     `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if resp.StatusCode != 200 {
		return nil, errors.New("lookup failed: " + r.Error)
	}
	vs.lookupMu.Lock()
	vs.lookupCache[vid] = lookupEntry{r.Locations, time.Now()}
	vs.lookupMu.Unlock()
	return r.Locations, nil
}

// replicate forwards a write/delete to the other replicas.
func (vs *VolumeServer) replicate(v *Volume, fid FileID, method string, n *Needle) error {
	if v.Replication.Copies() <= 1 {
		return nil
	}
	locs, err := vs.lookup(fid.VolumeID)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(locs))
	peers := 0
	for _, l := range locs {
		if l.URL == vs.URL {
			continue
		}
		peers++
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			u := fmt.Sprintf("http://%s/%s?type=replicate", target, fid)
			var body io.Reader
			if n != nil {
				body = bytes.NewReader(n.Data)
				u += fmt.Sprintf("&ttl=%ds&ts=%d", n.TTLSeconds, n.LastModified)
			}
			req, _ := http.NewRequest(method, u, body)
			if n != nil {
				req.Header.Set("Content-Type", n.Mime)
				req.Header.Set("X-File-Name", n.Name)
			}
			vs.Auth.SetAuth(req, fid.String())
			resp, err := vs.client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 300 && !(method == http.MethodDelete && resp.StatusCode == 404) {
				errs <- fmt.Errorf("replica %s returned %d", target, resp.StatusCode)
			}
		}(l.URL)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		return e
	}
	if peers < v.Replication.Copies()-1 {
		return fmt.Errorf("only %d of %d replicas reachable", peers+1, v.Replication.Copies())
	}
	return nil
}

// Handler returns the volume server HTTP API.
func (vs *VolumeServer) Handler() http.Handler {
	mux := http.NewServeMux()
	admin := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !vs.Auth.Verify(TokenFromRequest(r), AdminScope) {
				writeErr(w, 401, "missing or invalid cluster token")
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("/status", admin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"url": vs.URL, "data_center": vs.DataCenter, "rack": vs.Rack, "max_volumes": vs.Store.MaxVolumes, "volumes": vs.Store.Infos()})
	}))
	mux.HandleFunc("/admin/assign_volume", admin(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		vid, err := strconv.ParseUint(q.Get("volume"), 10, 32)
		if err != nil {
			writeErr(w, 400, "invalid volume")
			return
		}
		rp, err := ParseReplication(q.Get("replication"))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		ttl, err := ParseTTL(q.Get("ttl"))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := vs.Store.AddVolume(uint32(vid), q.Get("collection"), rp, ttl); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		go vs.Heartbeat()
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/admin/vacuum", admin(func(w http.ResponseWriter, r *http.Request) {
		vid, _ := strconv.ParseUint(r.URL.Query().Get("volume"), 10, 32)
		v := vs.Store.Get(uint32(vid))
		if v == nil {
			writeErr(w, 404, ErrNoSuchVol.Error())
			return
		}
		before := v.Info().Size
		if err := v.Compact(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		go vs.Heartbeat()
		writeJSON(w, 200, map[string]any{"before": before, "after": v.Info().Size})
	}))
	mux.HandleFunc("/admin/delete_volume", admin(func(w http.ResponseWriter, r *http.Request) {
		vid, _ := strconv.ParseUint(r.URL.Query().Get("volume"), 10, 32)
		if err := vs.Store.DeleteVolume(uint32(vid)); err != nil {
			writeErr(w, 404, err.Error())
			return
		}
		go vs.Heartbeat()
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/admin/readonly", admin(func(w http.ResponseWriter, r *http.Request) {
		vid, _ := strconv.ParseUint(r.URL.Query().Get("volume"), 10, 32)
		v := vs.Store.Get(uint32(vid))
		if v == nil {
			writeErr(w, 404, ErrNoSuchVol.Error())
			return
		}
		v.SetReadOnly(r.URL.Query().Get("readonly") != "false")
		go vs.Heartbeat()
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/", vs.handleFile)
	return mux
}

func (vs *VolumeServer) handleFile(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		writeJSON(w, 200, map[string]any{"service": "coffer-volume", "url": vs.URL})
		return
	}
	fid, err := ParseFileID(r.URL.Path)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !vs.Auth.Verify(TokenFromRequest(r), fid.String()) {
		writeErr(w, 401, "missing or invalid file token")
		return
	}
	v := vs.Store.Get(fid.VolumeID)
	if v == nil {
		writeErr(w, 404, ErrNoSuchVol.Error())
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		n, err := v.Read(fid.Key, fid.Cookie)
		if err != nil {
			code := 500
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCookie) {
				code = 404
			}
			writeErr(w, code, err.Error())
			return
		}
		etag := `"` + n.ETag() + `"`
		w.Header().Set("ETag", etag)
		ct := n.Mime
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		if n.Name != "" && r.URL.Query().Get("dl") == "true" {
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": n.Name}))
		}
		http.ServeContent(w, r, "", time.Unix(int64(n.LastModified), 0), bytes.NewReader(n.Data))
	case http.MethodPost, http.MethodPut:
		vs.handleWrite(w, r, v, fid)
	case http.MethodDelete:
		size, err := v.Delete(fid.Key, fid.Cookie)
		if err != nil {
			code := 500
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCookie) {
				code = 404
			}
			writeErr(w, code, err.Error())
			return
		}
		if r.URL.Query().Get("type") != "replicate" {
			if err := vs.replicate(v, fid, http.MethodDelete, nil); err != nil {
				writeErr(w, 500, "deleted locally, replication failed: "+err.Error())
				return
			}
		}
		writeJSON(w, 202, map[string]any{"size": size})
	default:
		writeErr(w, 405, "method not allowed")
	}
}

func (vs *VolumeServer) handleWrite(w http.ResponseWriter, r *http.Request, v *Volume, fid FileID) {
	limit := vs.MaxUploadMB << 20
	r.Body = http.MaxBytesReader(w, r.Body, limit+1<<20)
	n := &Needle{Cookie: fid.Cookie, ID: fid.Key}
	ct := r.Header.Get("Content-Type")
	mt, params, _ := mime.ParseMediaType(ct)
	if mt == "multipart/form-data" {
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				writeErr(w, 400, "no file part in multipart body")
				return
			}
			if p.FileName() == "" && p.FormName() != "file" {
				continue
			}
			data, err := io.ReadAll(p)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			n.Data = data
			n.Name = p.FileName()
			n.Mime = p.Header.Get("Content-Type")
			break
		}
	} else {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, 413, "upload too large or interrupted")
			return
		}
		n.Data = data
		n.Mime = ct
		n.Name = r.Header.Get("X-File-Name")
	}
	if int64(len(n.Data)) > limit {
		writeErr(w, 413, "upload exceeds limit")
		return
	}
	if n.Mime == "application/octet-stream" {
		n.Mime = ""
	}
	q := r.URL.Query()
	if t := q.Get("ttl"); t != "" {
		ttl, err := ParseTTL(t)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		n.TTLSeconds = ttl
	}
	if ts, err := strconv.ParseUint(q.Get("ts"), 10, 64); err == nil {
		n.LastModified = ts
	}
	size, err := v.Write(n)
	if err != nil {
		code := 500
		if errors.Is(err, ErrReadOnly) || errors.Is(err, ErrVolumeFull) {
			code = 507
			go vs.Heartbeat()
		} else if errors.Is(err, ErrCookie) {
			code = 409
		}
		writeErr(w, code, err.Error())
		return
	}
	if q.Get("type") != "replicate" {
		if err := vs.replicate(v, fid, http.MethodPut, n); err != nil {
			writeErr(w, 500, "replication failed: "+err.Error())
			return
		}
	}
	writeJSON(w, 201, map[string]any{"name": n.Name, "size": size, "eTag": n.ETag()})
}

// ---------------- client helpers (used by the filer) ----------------

// Client talks to the master and volume servers.
type Client struct {
	Master string
	Auth   *ClusterAuth
	HTTP   *http.Client
	mu     sync.Mutex
	cache  map[uint32]lookupEntry
}

func NewClient(master string, auth *ClusterAuth) *Client {
	return &Client{Master: master, Auth: auth, HTTP: &http.Client{Timeout: 120 * time.Second}, cache: map[uint32]lookupEntry{}}
}

func (c *Client) getJSON(method, u string, out any) error {
	req, _ := http.NewRequest(method, u, nil)
	c.Auth.SetAuth(req, AdminScope)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(body))
		}
		return fmt.Errorf("%s (status %d)", e.Error, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// Assign asks the master for a file id.
func (c *Client) Assign(collection, replication, ttl string) (*AssignResult, error) {
	var r AssignResult
	u := fmt.Sprintf("http://%s/dir/assign?collection=%s&replication=%s&ttl=%s", c.Master, urlq(collection), urlq(replication), urlq(ttl))
	if err := c.getJSON(http.MethodGet, u, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Lookup returns volume locations (cached briefly).
func (c *Client) Lookup(vid uint32) ([]Location, error) {
	c.mu.Lock()
	if e, ok := c.cache[vid]; ok && time.Since(e.at) < 15*time.Second {
		c.mu.Unlock()
		return e.locs, nil
	}
	c.mu.Unlock()
	var r struct {
		Locations []Location `json:"locations"`
	}
	if err := c.getJSON(http.MethodGet, fmt.Sprintf("http://%s/dir/lookup?volumeId=%d", c.Master, vid), &r); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cache[vid] = lookupEntry{r.Locations, time.Now()}
	c.mu.Unlock()
	return r.Locations, nil
}

func (c *Client) invalidate(vid uint32) {
	c.mu.Lock()
	delete(c.cache, vid)
	c.mu.Unlock()
}

// Upload stores data and returns the fid. Retries on a fresh assignment.
func (c *Client) Upload(data []byte, name, mimeType, collection, replication, ttl string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		a, err := c.Assign(collection, replication, ttl)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt*200) * time.Millisecond)
			continue
		}
		u := "http://" + a.URL + "/" + a.Fid
		if ttl != "" {
			u += "?ttl=" + urlq(ttl)
		}
		req, _ := http.NewRequest(http.MethodPut, u, bytes.NewReader(data))
		if mimeType != "" {
			req.Header.Set("Content-Type", mimeType)
		}
		if name != "" {
			req.Header.Set("X-File-Name", name)
		}
		if a.Auth != "" {
			req.Header.Set("Authorization", "Bearer "+a.Auth)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			lastErr = fmt.Errorf("upload to %s failed: %d %s", a.URL, resp.StatusCode, strings.TrimSpace(string(body)))
			continue
		}
		return a.Fid, nil
	}
	return "", lastErr
}

// Fetch downloads a blob (whole), trying each replica.
func (c *Client) Fetch(fidStr string) ([]byte, error) {
	fid, err := ParseFileID(fidStr)
	if err != nil {
		return nil, err
	}
	locs, err := c.Lookup(fid.VolumeID)
	if err != nil {
		return nil, err
	}
	var lastErr error = ErrNotFound
	for _, l := range locs {
		req, _ := http.NewRequest(http.MethodGet, "http://"+l.URL+"/"+fidStr, nil)
		c.Auth.SetAuth(req, fidStr)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && err == nil {
			return data, nil
		}
		lastErr = fmt.Errorf("fetch %s from %s: status %d", fidStr, l.URL, resp.StatusCode)
	}
	c.invalidate(fid.VolumeID)
	return nil, lastErr
}

// Delete removes a blob (the volume server replicates the delete).
func (c *Client) Delete(fidStr string) error {
	fid, err := ParseFileID(fidStr)
	if err != nil {
		return err
	}
	locs, err := c.Lookup(fid.VolumeID)
	if err != nil {
		return err
	}
	if len(locs) == 0 {
		return ErrNotFound
	}
	req, _ := http.NewRequest(http.MethodDelete, "http://"+locs[0].URL+"/"+fidStr, nil)
	c.Auth.SetAuth(req, fidStr)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		return fmt.Errorf("delete %s: status %d", fidStr, resp.StatusCode)
	}
	return nil
}

// Status fetches the master topology.
func (c *Client) Status() (*TopologyStatus, error) {
	var st TopologyStatus
	if err := c.getJSON(http.MethodGet, "http://"+c.Master+"/dir/status", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Call performs an admin call on the master and decodes the JSON result.
func (c *Client) Call(path string, out any) error {
	return c.getJSON(http.MethodPost, "http://"+c.Master+path, out)
}
