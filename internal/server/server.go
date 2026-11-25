// Package server assembles a Coffer node: master, volume server, secrets
// core, filer, S3 gateway, HTTP API and web UI.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"coffer/internal/filer"
	"coffer/internal/kvstore"
	"coffer/internal/s3api"
	"coffer/internal/storage"
	"coffer/internal/ui"
	"coffer/internal/vault"
)

// Config for `coffer server`.
type Config struct {
	Dir           string
	IP            string // advertised address for volume server
	Bind          string // listen address
	APIPort       int
	MasterPort    int
	VolumePort    int
	S3Port        int
	Master        string // external master host:port; empty = embedded
	NoVolume      bool
	VolumeMax     int
	VolumeSizeMB  int64
	Replication   string
	ClusterSecret string
	DataCenter    string
	Rack          string
	ChunkSizeMB   int64
	TLSCert       string
	TLSKey        string
	S3Domain      string
	Region        string
	Dev           bool
	DevRootToken  string
	UnsealKeyFile string
	PublicURL     string // externally reachable API URL (for share links)
}

// Server is a running node.
type Server struct {
	cfg     Config
	Core    *vault.Core
	Filer   *filer.Filer
	Master  *storage.Master
	Volume  *storage.VolumeServer
	S3      *s3api.Server
	stores  []*kvstore.Store
	servers []*http.Server
	stop    chan struct{}

	statsMu   sync.Mutex
	statsAt   time.Time
	statsVal  filer.Stats
	ShareBase string
}

func (c *Config) defaults() {
	if c.Dir == "" {
		c.Dir = "./coffer-data"
	}
	if c.Bind == "" {
		c.Bind = "0.0.0.0"
	}
	if c.IP == "" {
		c.IP = "127.0.0.1"
	}
	if c.APIPort == 0 {
		c.APIPort = 8200
	}
	if c.MasterPort == 0 {
		c.MasterPort = 9333
	}
	if c.VolumePort == 0 {
		c.VolumePort = 8080
	}
	if c.S3Port == 0 {
		c.S3Port = 8333
	}
	if c.VolumeMax == 0 {
		c.VolumeMax = 16
	}
	if c.VolumeSizeMB == 0 {
		c.VolumeSizeMB = 1024
	}
	if c.Replication == "" {
		c.Replication = "000"
	}
	if c.ChunkSizeMB == 0 {
		c.ChunkSizeMB = 4
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.DataCenter == "" {
		c.DataCenter = "dc1"
	}
	if c.Rack == "" {
		c.Rack = "rack1"
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// clusterSecret loads or creates the shared secret used between components.
func clusterSecret(cfg *Config) (string, error) {
	if cfg.ClusterSecret != "" {
		return cfg.ClusterSecret, nil
	}
	if v := os.Getenv("COFFER_CLUSTER_SECRET"); v != "" {
		return v, nil
	}
	if cfg.Master != "" {
		return "", nil // joining an external cluster without a secret
	}
	p := filepath.Join(cfg.Dir, "cluster.secret")
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	s := randomHex(32)
	if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
		return "", err
	}
	return s, nil
}

// New builds all components (nothing listens yet).
func New(cfg Config) (*Server, error) {
	cfg.defaults()
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	secret, err := clusterSecret(&cfg)
	if err != nil {
		return nil, err
	}
	auth := &storage.ClusterAuth{Secret: []byte(secret)}
	s := &Server{cfg: cfg, stop: make(chan struct{})}

	masterAddr := cfg.Master
	if masterAddr == "" {
		m, err := storage.NewMaster(filepath.Join(cfg.Dir, "master"), cfg.VolumeSizeMB<<20, cfg.Replication, auth)
		if err != nil {
			return nil, fmt.Errorf("master: %w", err)
		}
		s.Master = m
		masterAddr = fmt.Sprintf("%s:%d", cfg.IP, cfg.MasterPort)
	}
	if !cfg.NoVolume {
		st, err := storage.OpenStore(filepath.Join(cfg.Dir, "volume"), cfg.VolumeMax, cfg.VolumeSizeMB<<20)
		if err != nil {
			return nil, fmt.Errorf("volume store: %w", err)
		}
		s.Volume = storage.NewVolumeServer(st, fmt.Sprintf("%s:%d", cfg.IP, cfg.VolumePort), "", []string{masterAddr}, cfg.DataCenter, cfg.Rack, auth)
	}

	vstore, err := kvstore.Open(filepath.Join(cfg.Dir, "vault"))
	if err != nil {
		return nil, fmt.Errorf("secrets storage: %w", err)
	}
	fstore, err := kvstore.Open(filepath.Join(cfg.Dir, "filer"))
	if err != nil {
		return nil, fmt.Errorf("filer storage: %w", err)
	}
	s.stores = []*kvstore.Store{vstore, fstore}
	s.Core = vault.NewCore(vstore)
	client := storage.NewClient(masterAddr, auth)
	s.Filer = filer.New(fstore, client, s.Core)
	s.Filer.ChunkSize = cfg.ChunkSizeMB << 20
	s.Filer.DefaultRep = cfg.Replication
	s.Core.OnSeal = append(s.Core.OnSeal, s.Filer.ForgetKeys)
	s.S3 = &s3api.Server{Filer: s.Filer, Core: s.Core, Creds: &s3Creds{core: s.Core}, Region: cfg.Region, Domain: cfg.S3Domain}
	s.registerSys()
	if _, err := s.Filer.Mkdir(filer.BucketsDir, "system"); err != nil {
		return nil, err
	}
	scheme := "http"
	if cfg.TLSCert != "" {
		scheme = "https"
	}
	s.ShareBase = cfg.PublicURL
	if s.ShareBase == "" {
		s.ShareBase = fmt.Sprintf("%s://%s:%d", scheme, cfg.IP, cfg.APIPort)
	}
	return s, nil
}

// APIHandler serves /v1, /share and /ui.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(ui.Files, "static")
	fileServer := http.FileServer(http.FS(static))
	mux.Handle("/ui/", http.StripPrefix("/ui", securityHeaders(fileServer)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		writeErrors(w, 404, "not found")
	})
	mux.HandleFunc("/share/", s.handleShareDownload)
	mux.HandleFunc("/v1/fs", s.handleFS)
	mux.HandleFunc("/v1/fs/", s.handleFS)
	mux.HandleFunc("/v1/", s.handleLogical)
	return logRequests(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func logRequests(h http.Handler) http.Handler {
	quiet := os.Getenv("COFFER_LOG_REQUESTS") == ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if quiet {
			h.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		log.Printf("api: %s %s %d %s", r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) listen(name, addr string, h http.Handler, useTLS bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	s.servers = append(s.servers, srv)
	go func() {
		var err error
		if useTLS {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			err = srv.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s server error: %v", name, err)
		}
	}()
	log.Printf("%-7s listening on %s", name, addr)
	return nil
}

// Start opens all listeners and background loops.
func (s *Server) Start() error {
	c := s.cfg
	tlsOn := c.TLSCert != "" && c.TLSKey != ""
	if s.Master != nil {
		if err := s.listen("master", fmt.Sprintf("%s:%d", c.Bind, c.MasterPort), s.Master.Handler(), false); err != nil {
			return err
		}
		go s.Master.RunMaintenance(s.stop)
	}
	if s.Volume != nil {
		if err := s.listen("volume", fmt.Sprintf("%s:%d", c.Bind, c.VolumePort), s.Volume.Handler(), false); err != nil {
			return err
		}
		go s.Volume.RunHeartbeat(s.stop)
	}
	if err := s.listen("s3", fmt.Sprintf("%s:%d", c.Bind, c.S3Port), s.S3, tlsOn); err != nil {
		return err
	}
	if err := s.listen("api", fmt.Sprintf("%s:%d", c.Bind, c.APIPort), s.APIHandler(), tlsOn); err != nil {
		return err
	}
	go s.sweepLoop()
	if c.Dev {
		if err := s.devInit(); err != nil {
			return err
		}
	} else if c.UnsealKeyFile != "" {
		if err := s.autoUnseal(c.UnsealKeyFile); err != nil {
			log.Printf("auto-unseal failed: %v", err)
		}
	}
	return nil
}

func (s *Server) sweepLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if n := s.Filer.SweepExpired(); n > 0 {
				log.Printf("filer: removed %d expired file(s)", n)
			}
		}
	}
}

func (s *Server) autoUnseal(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var keys []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	if err := s.Core.UnsealWithKeys(keys); err != nil {
		return err
	}
	log.Printf("core: auto-unsealed using %s", path)
	return nil
}

// devInit initializes with a single key and unseals automatically.
func (s *Server) devInit() error {
	keyFile := filepath.Join(s.cfg.Dir, "dev-unseal.key")
	if !s.Core.Initialized() {
		res, err := s.Core.Initialize(1, 1)
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyFile, []byte(res.Keys[0]+"\n"), 0o600); err != nil {
			return err
		}
		if err := s.Core.UnsealWithKeys(res.Keys); err != nil {
			return err
		}
		tok := res.RootToken
		if s.cfg.DevRootToken != "" {
			if tok, err = s.Core.CreateRootToken(s.cfg.DevRootToken); err != nil {
				return err
			}
		}
		s.Filer.Mkdir(filer.BucketsDir, "root")
		printDevBanner(res.Keys[0], tok, s.cfg)
		return nil
	}
	if err := s.autoUnseal(keyFile); err != nil {
		return fmt.Errorf("dev mode: existing data in %s could not be auto-unsealed: %w", s.cfg.Dir, err)
	}
	if s.cfg.DevRootToken != "" {
		s.Core.CreateRootToken(s.cfg.DevRootToken)
	}
	log.Printf("dev mode: reusing data in %s (root token unchanged)", s.cfg.Dir)
	return nil
}

func printDevBanner(key, token string, c Config) {
	fmt.Printf(`
==> Coffer is running in DEV MODE. Data in %s is auto-unsealed: do not use in production.

    Web UI:       http://%s:%d/ui/
    API address:  http://%s:%d
    S3 endpoint:  http://%s:%d
    Unseal key:   %s
    Root token:   %s

    export COFFER_ADDR=http://%s:%d
    export COFFER_TOKEN=%s

`, c.Dir, c.IP, c.APIPort, c.IP, c.APIPort, c.IP, c.S3Port, key, token, c.IP, c.APIPort, token)
}

// Shutdown stops listeners and flushes storage.
func (s *Server) Shutdown(ctx context.Context) {
	close(s.stop)
	for _, srv := range s.servers {
		srv.Shutdown(ctx)
	}
	s.Core.Seal()
	if s.Volume != nil {
		s.Volume.Store.Close()
	}
	for _, st := range s.stores {
		st.Close()
	}
}

func urlPathEscape(s string) string { return url.PathEscape(s) }
