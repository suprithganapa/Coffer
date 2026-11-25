package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	HeartbeatInterval = 3 * time.Second
	NodeDeadAfter     = 12 * time.Second
	seqBatch          = 10000
)

// DataNode is a volume server as seen by the master.
type DataNode struct {
	URL        string                `json:"url"`
	PublicURL  string                `json:"public_url"`
	DataCenter string                `json:"data_center"`
	Rack       string                `json:"rack"`
	MaxVolumes int                   `json:"max_volumes"`
	Volumes    map[uint32]VolumeInfo `json:"-"`
	LastSeen   time.Time             `json:"last_seen"`
	pending    int
}

func (n *DataNode) alive() bool { return time.Since(n.LastSeen) < NodeDeadAfter }
func (n *DataNode) free() int   { return n.MaxVolumes - len(n.Volumes) - n.pending }

// Heartbeat is sent by volume servers.
type Heartbeat struct {
	URL        string       `json:"url"`
	PublicURL  string       `json:"public_url"`
	DataCenter string       `json:"data_center"`
	Rack       string       `json:"rack"`
	MaxVolumes int          `json:"max_volumes"`
	Volumes    []VolumeInfo `json:"volumes"`
}

// Location of a volume replica.
type Location struct {
	URL       string `json:"url"`
	PublicURL string `json:"publicUrl"`
}

// AssignResult is returned by /dir/assign.
type AssignResult struct {
	Fid       string `json:"fid"`
	URL       string `json:"url"`
	PublicURL string `json:"publicUrl"`
	Count     int    `json:"count"`
	Auth      string `json:"auth,omitempty"`
	Error     string `json:"error,omitempty"`
}

type masterState struct {
	MaxVolumeID uint32 `json:"max_volume_id"`
	SeqCeiling  uint64 `json:"sequence_ceiling"`
}

// Master tracks topology, assigns file ids and grows volumes.
type Master struct {
	mu            sync.Mutex
	growMu        sync.Mutex
	nodes         map[string]*DataNode
	dir           string
	state         masterState
	seq           uint64
	SizeLimit     int64
	DefaultRepl   string
	GrowCount     int
	GarbageThresh float64
	Auth          *ClusterAuth
	client        *http.Client
	started       time.Time
}

// NewMaster loads persisted state from dir.
func NewMaster(dir string, sizeLimit int64, defaultRepl string, auth *ClusterAuth) (*Master, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if _, err := ParseReplication(defaultRepl); err != nil {
		return nil, err
	}
	m := &Master{
		nodes: map[string]*DataNode{}, dir: dir, SizeLimit: sizeLimit,
		DefaultRepl: defaultRepl, GrowCount: 2, GarbageThresh: 0.3, Auth: auth,
		client: &http.Client{Timeout: 60 * time.Second}, started: time.Now(),
	}
	if b, err := os.ReadFile(filepath.Join(dir, "master.json")); err == nil {
		json.Unmarshal(b, &m.state)
	}
	// skip any ids that may have been handed out before a crash
	m.seq = m.state.SeqCeiling
	if err := m.persist(m.seq + seqBatch); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Master) persist(ceiling uint64) error {
	m.state.SeqCeiling = ceiling
	b, _ := json.Marshal(m.state)
	tmp := filepath.Join(m.dir, "master.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.dir, "master.json"))
}

func (m *Master) nextKeys(count int) (uint64, error) {
	start := m.seq + 1
	m.seq += uint64(count)
	if m.seq >= m.state.SeqCeiling {
		if err := m.persist(m.seq + seqBatch); err != nil {
			return 0, err
		}
	}
	return start, nil
}

// HandleHeartbeat records volume server state.
func (m *Master) HandleHeartbeat(hb Heartbeat) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[hb.URL]
	if !ok {
		n = &DataNode{URL: hb.URL}
		m.nodes[hb.URL] = n
		log.Printf("master: volume server joined %s (dc=%s rack=%s)", hb.URL, hb.DataCenter, hb.Rack)
	}
	n.PublicURL = hb.PublicURL
	if n.PublicURL == "" {
		n.PublicURL = hb.URL
	}
	n.DataCenter = orDefault(hb.DataCenter, "DefaultDataCenter")
	n.Rack = orDefault(hb.Rack, "DefaultRack")
	n.MaxVolumes = hb.MaxVolumes
	n.LastSeen = time.Now()
	n.Volumes = map[uint32]VolumeInfo{}
	changed := false
	for _, v := range hb.Volumes {
		n.Volumes[v.ID] = v
		if v.ID > m.state.MaxVolumeID {
			m.state.MaxVolumeID = v.ID
			changed = true
		}
	}
	if changed {
		m.persist(m.state.SeqCeiling)
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

type volumeView struct {
	info      VolumeInfo
	locations []*DataNode
}

// volumesLocked builds vid -> replicas from live nodes.
func (m *Master) volumesLocked() map[uint32]*volumeView {
	out := map[uint32]*volumeView{}
	for _, n := range m.nodes {
		if !n.alive() {
			continue
		}
		for id, v := range n.Volumes {
			vv, ok := out[id]
			if !ok {
				vv = &volumeView{info: v}
				out[id] = vv
			}
			if v.Size > vv.info.Size {
				vv.info.Size = v.Size
			}
			if v.ReadOnly {
				vv.info.ReadOnly = true
			}
			vv.locations = append(vv.locations, n)
		}
	}
	return out
}

// Lookup returns live replica locations of a volume.
func (m *Master) Lookup(vid uint32) []Location {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Location
	for _, n := range m.nodes {
		if !n.alive() {
			continue
		}
		if _, ok := n.Volumes[vid]; ok {
			out = append(out, Location{URL: n.URL, PublicURL: n.PublicURL})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func (m *Master) writableLocked(collection string, rp ReplicaPlacement, ttl uint32) []*volumeView {
	var out []*volumeView
	for _, vv := range m.volumesLocked() {
		i := vv.info
		if i.Collection != collection || i.Replication != rp.String() || i.TTLSeconds != ttl {
			continue
		}
		if i.ReadOnly || len(vv.locations) < rp.Copies() {
			continue
		}
		if m.SizeLimit > 0 && i.Size >= m.SizeLimit*95/100 {
			continue
		}
		out = append(out, vv)
	}
	return out
}

// Assign reserves count file ids in a writable volume, growing if needed.
func (m *Master) Assign(collection, replication, ttlStr string, count int) (*AssignResult, error) {
	if count <= 0 {
		count = 1
	}
	if replication == "" {
		replication = m.DefaultRepl
	}
	rp, err := ParseReplication(replication)
	if err != nil {
		return nil, err
	}
	ttl, err := ParseTTL(ttlStr)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		m.mu.Lock()
		w := m.writableLocked(collection, rp, ttl)
		if len(w) > 0 {
			vv := w[rand.Intn(len(w))]
			key, err := m.nextKeys(count)
			if err != nil {
				m.mu.Unlock()
				return nil, err
			}
			loc := vv.locations[rand.Intn(len(vv.locations))]
			url, pub := loc.URL, loc.PublicURL
			fid := FileID{VolumeID: vv.info.ID, Key: key, Cookie: RandomCookie()}.String()
			m.mu.Unlock()
			return &AssignResult{Fid: fid, URL: url, PublicURL: pub, Count: count, Auth: m.Auth.Sign(fid, 10*time.Minute)}, nil
		}
		m.mu.Unlock()
		if attempt == 0 {
			if _, err := m.Grow(collection, rp, ttl, m.GrowCount); err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("no writable volumes available")
}

// pickNodes chooses nodes satisfying a replica placement.
func (m *Master) pickNodesLocked(rp ReplicaPlacement) ([]*DataNode, error) {
	var cands []*DataNode
	for _, n := range m.nodes {
		if n.alive() && n.free() > 0 {
			cands = append(cands, n)
		}
	}
	if len(cands) == 0 {
		return nil, errors.New("no volume servers with free slots")
	}
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	for _, primary := range cands {
		picked := []*DataNode{primary}
		used := map[string]bool{primary.URL: true}
		// same rack, other servers
		for _, n := range cands {
			if len(picked) >= 1+rp.SameRack {
				break
			}
			if !used[n.URL] && n.DataCenter == primary.DataCenter && n.Rack == primary.Rack {
				picked = append(picked, n)
				used[n.URL] = true
			}
		}
		if len(picked) < 1+rp.SameRack {
			continue
		}
		racks := map[string]bool{primary.Rack: true}
		got := 0
		for _, n := range cands {
			if got >= rp.DiffRack {
				break
			}
			if !used[n.URL] && n.DataCenter == primary.DataCenter && !racks[n.Rack] {
				picked = append(picked, n)
				used[n.URL] = true
				racks[n.Rack] = true
				got++
			}
		}
		if got < rp.DiffRack {
			continue
		}
		dcs := map[string]bool{primary.DataCenter: true}
		got = 0
		for _, n := range cands {
			if got >= rp.DiffDC {
				break
			}
			if !used[n.URL] && !dcs[n.DataCenter] {
				picked = append(picked, n)
				used[n.URL] = true
				dcs[n.DataCenter] = true
				got++
			}
		}
		if got < rp.DiffDC {
			continue
		}
		return picked, nil
	}
	return nil, fmt.Errorf("not enough volume servers to satisfy replication %s", rp)
}

// Grow creates count new volumes for a layout.
func (m *Master) Grow(collection string, rp ReplicaPlacement, ttl uint32, count int) ([]uint32, error) {
	m.growMu.Lock()
	defer m.growMu.Unlock()
	var created []uint32
	var lastErr error
	for i := 0; i < count; i++ {
		m.mu.Lock()
		nodes, err := m.pickNodesLocked(rp)
		if err != nil {
			m.mu.Unlock()
			lastErr = err
			break
		}
		m.state.MaxVolumeID++
		vid := m.state.MaxVolumeID
		m.persist(m.state.SeqCeiling)
		for _, n := range nodes {
			n.pending++
		}
		m.mu.Unlock()

		ok := true
		for _, n := range nodes {
			u := fmt.Sprintf("http://%s/admin/assign_volume?volume=%d&collection=%s&replication=%s&ttl=%ds",
				n.URL, vid, urlq(collection), rp.String(), ttl)
			if err := m.adminCall(u); err != nil {
				lastErr = fmt.Errorf("allocate volume %d on %s: %w", vid, n.URL, err)
				ok = false
				break
			}
		}
		m.mu.Lock()
		for _, n := range nodes {
			n.pending--
			if ok {
				n.Volumes[vid] = VolumeInfo{ID: vid, Collection: collection, Replication: rp.String(), TTLSeconds: ttl, Size: SuperBlockSize}
			}
		}
		m.mu.Unlock()
		if ok {
			created = append(created, vid)
			log.Printf("master: grew volume %d collection=%q replication=%s on %d node(s)", vid, collection, rp, len(nodes))
		}
	}
	if len(created) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return created, nil
}

func (m *Master) adminCall(u string) error {
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	m.Auth.SetAuth(req, AdminScope)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("status %d: %s", resp.StatusCode, e.Error)
	}
	return nil
}

// Vacuum compacts volumes whose garbage ratio exceeds threshold.
func (m *Master) Vacuum(threshold float64) map[uint32]string {
	if threshold <= 0 {
		threshold = m.GarbageThresh
	}
	m.mu.Lock()
	type job struct {
		vid   uint32
		nodes []string
	}
	var jobs []job
	for vid, vv := range m.volumesLocked() {
		data := vv.info.Size - SuperBlockSize
		var garbage float64
		for _, n := range vv.locations {
			vi := n.Volumes[vid]
			if data > 0 && float64(vi.DeletedBytes)/float64(data) > garbage {
				garbage = float64(vi.DeletedBytes) / float64(data)
			}
		}
		if garbage >= threshold {
			j := job{vid: vid}
			for _, n := range vv.locations {
				j.nodes = append(j.nodes, n.URL)
			}
			jobs = append(jobs, j)
		}
	}
	m.mu.Unlock()
	res := map[uint32]string{}
	for _, j := range jobs {
		status := "compacted"
		for _, n := range j.nodes {
			if err := m.adminCall(fmt.Sprintf("http://%s/admin/vacuum?volume=%d", n, j.vid)); err != nil {
				status = err.Error()
			}
		}
		res[j.vid] = status
		log.Printf("master: vacuum volume %d: %s", j.vid, status)
	}
	return res
}

// DeleteCollection removes all volumes of a collection.
func (m *Master) DeleteCollection(collection string) error {
	if collection == "" {
		return errors.New("collection required")
	}
	m.mu.Lock()
	type target struct {
		node string
		vid  uint32
	}
	var ts []target
	for _, n := range m.nodes {
		for vid, v := range n.Volumes {
			if v.Collection == collection {
				ts = append(ts, target{n.URL, vid})
			}
		}
	}
	m.mu.Unlock()
	var lastErr error
	for _, t := range ts {
		if err := m.adminCall(fmt.Sprintf("http://%s/admin/delete_volume?volume=%d", t.node, t.vid)); err != nil {
			lastErr = err
			continue
		}
		m.mu.Lock()
		if n := m.nodes[t.node]; n != nil {
			delete(n.Volumes, t.vid)
		}
		m.mu.Unlock()
	}
	return lastErr
}

// RunMaintenance periodically vacuums and drops long-dead nodes.
func (m *Master) RunMaintenance(stop <-chan struct{}) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.Vacuum(m.GarbageThresh)
			m.mu.Lock()
			for k, n := range m.nodes {
				if time.Since(n.LastSeen) > 24*time.Hour {
					delete(m.nodes, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

// TopologyStatus is the JSON view of the cluster.
type TopologyStatus struct {
	Started     time.Time        `json:"started"`
	SizeLimit   int64            `json:"volume_size_limit"`
	DefaultRepl string           `json:"default_replication"`
	MaxVolumeID uint32           `json:"max_volume_id"`
	DataCenters []DCStatus       `json:"data_centers"`
	Volumes     []VolumeStatus   `json:"volumes"`
	Totals      map[string]int64 `json:"totals"`
}

type DCStatus struct {
	Name  string       `json:"name"`
	Racks []RackStatus `json:"racks"`
}

type RackStatus struct {
	Name  string       `json:"name"`
	Nodes []NodeStatus `json:"nodes"`
}

type NodeStatus struct {
	URL        string    `json:"url"`
	PublicURL  string    `json:"public_url"`
	Alive      bool      `json:"alive"`
	LastSeen   time.Time `json:"last_seen"`
	MaxVolumes int       `json:"max_volumes"`
	Volumes    int       `json:"volumes"`
	UsedBytes  int64     `json:"used_bytes"`
}

type VolumeStatus struct {
	VolumeInfo
	Locations []string `json:"locations"`
	Writable  bool     `json:"writable"`
}

// Status returns the full topology.
func (m *Master) Status() TopologyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := TopologyStatus{Started: m.started, SizeLimit: m.SizeLimit, DefaultRepl: m.DefaultRepl, MaxVolumeID: m.state.MaxVolumeID, Totals: map[string]int64{}}
	dcs := map[string]map[string][]NodeStatus{}
	for _, n := range m.nodes {
		var used int64
		for _, v := range n.Volumes {
			used += v.Size
		}
		ns := NodeStatus{URL: n.URL, PublicURL: n.PublicURL, Alive: n.alive(), LastSeen: n.LastSeen, MaxVolumes: n.MaxVolumes, Volumes: len(n.Volumes), UsedBytes: used}
		if dcs[n.DataCenter] == nil {
			dcs[n.DataCenter] = map[string][]NodeStatus{}
		}
		dcs[n.DataCenter][n.Rack] = append(dcs[n.DataCenter][n.Rack], ns)
		st.Totals["nodes"]++
		if ns.Alive {
			st.Totals["alive_nodes"]++
			st.Totals["slots"] += int64(n.MaxVolumes)
		}
	}
	for dc, racks := range dcs {
		d := DCStatus{Name: dc}
		for rk, nodes := range racks {
			sort.Slice(nodes, func(i, j int) bool { return nodes[i].URL < nodes[j].URL })
			d.Racks = append(d.Racks, RackStatus{Name: rk, Nodes: nodes})
		}
		sort.Slice(d.Racks, func(i, j int) bool { return d.Racks[i].Name < d.Racks[j].Name })
		st.DataCenters = append(st.DataCenters, d)
	}
	sort.Slice(st.DataCenters, func(i, j int) bool { return st.DataCenters[i].Name < st.DataCenters[j].Name })
	for vid, vv := range m.volumesLocked() {
		vs := VolumeStatus{VolumeInfo: vv.info}
		rp, _ := ParseReplication(vv.info.Replication)
		for _, n := range vv.locations {
			vs.Locations = append(vs.Locations, n.URL)
			if vi, ok := n.Volumes[vid]; ok {
				if vi.FileCount > vs.FileCount {
					vs.FileCount = vi.FileCount
				}
				if vi.DeletedBytes > vs.DeletedBytes {
					vs.DeletedBytes = vi.DeletedBytes
				}
				if vi.DeleteCount > vs.DeleteCount {
					vs.DeleteCount = vi.DeleteCount
				}
			}
		}
		sort.Strings(vs.Locations)
		vs.Writable = !vs.ReadOnly && len(vv.locations) >= rp.Copies() && (m.SizeLimit == 0 || vs.Size < m.SizeLimit*95/100)
		st.Volumes = append(st.Volumes, vs)
		st.Totals["volumes"]++
		st.Totals["used_bytes"] += vs.Size * int64(len(vv.locations))
		st.Totals["files"] += int64(vs.FileCount)
	}
	sort.Slice(st.Volumes, func(i, j int) bool { return st.Volumes[i].ID < st.Volumes[j].ID })
	return st
}

// ---------------- HTTP ----------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err string) {
	writeJSON(w, code, map[string]string{"error": err})
}

func (m *Master) authorized(r *http.Request) bool {
	return m.Auth.Verify(TokenFromRequest(r), AdminScope)
}

// Handler returns the master HTTP API.
func (m *Master) Handler() http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !m.authorized(r) {
				writeErr(w, http.StatusUnauthorized, "missing or invalid cluster token")
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("/dir/assign", guard(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		count, _ := strconv.Atoi(q.Get("count"))
		res, err := m.Assign(q.Get("collection"), q.Get("replication"), q.Get("ttl"), count)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSON(w, 200, res)
	}))
	mux.HandleFunc("/dir/lookup", guard(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("volumeId")
		if i := indexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		vid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			writeErr(w, 400, "invalid volumeId")
			return
		}
		locs := m.Lookup(uint32(vid))
		if len(locs) == 0 {
			writeErr(w, 404, "volume not found")
			return
		}
		writeJSON(w, 200, map[string]any{"volumeId": v, "locations": locs})
	}))
	mux.HandleFunc("/dir/heartbeat", guard(func(w http.ResponseWriter, r *http.Request) {
		var hb Heartbeat
		if err := json.NewDecoder(r.Body).Decode(&hb); err != nil || hb.URL == "" {
			writeErr(w, 400, "invalid heartbeat")
			return
		}
		m.HandleHeartbeat(hb)
		writeJSON(w, 200, map[string]any{"volume_size_limit": m.SizeLimit})
	}))
	mux.HandleFunc("/dir/status", guard(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, m.Status()) }))
	mux.HandleFunc("/cluster/status", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"is_leader": true, "leader": r.Host, "started": m.started})
	}))
	mux.HandleFunc("/vol/grow", guard(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		count, _ := strconv.Atoi(q.Get("count"))
		if count <= 0 {
			count = 1
		}
		repl := q.Get("replication")
		if repl == "" {
			repl = m.DefaultRepl
		}
		rp, err := ParseReplication(repl)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		ttl, err := ParseTTL(q.Get("ttl"))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		ids, err := m.Grow(q.Get("collection"), rp, ttl, count)
		if err != nil {
			writeErr(w, 503, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"created": ids})
	}))
	mux.HandleFunc("/vol/vacuum", guard(func(w http.ResponseWriter, r *http.Request) {
		th, _ := strconv.ParseFloat(r.URL.Query().Get("garbageThreshold"), 64)
		writeJSON(w, 200, map[string]any{"result": m.Vacuum(th)})
	}))
	mux.HandleFunc("/col/delete", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := m.DeleteCollection(r.URL.Query().Get("collection")); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	return mux
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
