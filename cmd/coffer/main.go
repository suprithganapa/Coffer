// Command coffer runs Coffer servers and provides a CLI client.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"coffer/internal/server"
	"coffer/internal/storage"
	"coffer/internal/vault"
)

const usage = `Coffer — sealed secrets and distributed storage in one system.

Usage: coffer <command> [options]

Servers:
  server        Run an all-in-one node (master + volume + secrets + filer + S3 + UI)
  master        Run a standalone storage master
  volume        Run a standalone volume server

Operator:
  operator init | unseal | seal | status | rotate | rekey | generate-root
  status        Show seal status

Secrets:
  login         Authenticate (token, userpass, approle) and store the token
  kv            get | put | patch | list | delete | undelete | destroy | metadata
  read | write | list | delete   Generic API access to any path
  token         create | lookup | renew | revoke
  policy        list | read | write | delete
  secrets       list | enable | disable
  auth          list | enable | disable

Storage:
  fs            ls | put | get | cat | rm | mkdir | mv | cp | share | encrypt | stat
  s3            keys-create | keys-list | keys-delete
  cluster       status | grow | vacuum

  version       Print version

Environment: COFFER_ADDR (default http://127.0.0.1:8200), COFFER_TOKEN
Run "coffer <command> -h" for command options.
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "server":
		err = runServer(args)
	case "master":
		err = runMaster(args)
	case "volume":
		err = runVolume(args)
	case "version", "-v", "--version":
		fmt.Println("coffer", vault.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = runClient(cmd, args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Println("shutting down...")
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var c server.Config
	fs.StringVar(&c.Dir, "dir", "./coffer-data", "data directory")
	fs.StringVar(&c.IP, "ip", "127.0.0.1", "address other nodes and clients use to reach this node")
	fs.StringVar(&c.Bind, "bind", "0.0.0.0", "listen address")
	fs.IntVar(&c.APIPort, "port", 8200, "API + web UI port")
	fs.IntVar(&c.MasterPort, "master.port", 9333, "embedded master port")
	fs.IntVar(&c.VolumePort, "volume.port", 8080, "embedded volume server port")
	fs.IntVar(&c.S3Port, "s3.port", 8333, "S3 gateway port")
	fs.StringVar(&c.Master, "master", "", "use an external master host:port instead of the embedded one")
	fs.BoolVar(&c.NoVolume, "volume.disable", false, "do not run an embedded volume server")
	fs.IntVar(&c.VolumeMax, "volume.max", 16, "max number of volumes on the embedded volume server")
	fs.Int64Var(&c.VolumeSizeMB, "volume.sizeLimitMB", 1024, "volume size limit in MB")
	fs.StringVar(&c.Replication, "replication", "000", "default replication (xyz: other DCs, other racks, same rack)")
	fs.StringVar(&c.ClusterSecret, "cluster.secret", "", "shared secret between components (env COFFER_CLUSTER_SECRET)")
	fs.StringVar(&c.DataCenter, "dataCenter", "dc1", "data center of the embedded volume server")
	fs.StringVar(&c.Rack, "rack", "rack1", "rack of the embedded volume server")
	fs.Int64Var(&c.ChunkSizeMB, "chunkSizeMB", 4, "file chunk size in MB")
	fs.StringVar(&c.TLSCert, "tls.cert", "", "TLS certificate for API and S3")
	fs.StringVar(&c.TLSKey, "tls.key", "", "TLS key for API and S3")
	fs.StringVar(&c.S3Domain, "s3.domain", "", "domain for virtual-hosted-style S3 requests")
	fs.StringVar(&c.Region, "s3.region", "us-east-1", "S3 region name")
	fs.BoolVar(&c.Dev, "dev", false, "development mode: auto init + unseal")
	fs.StringVar(&c.DevRootToken, "dev.root-token", "", "fixed root token id in dev mode")
	fs.StringVar(&c.DevRootToken, "dev-root-token", "", "same as -dev.root-token (PowerShell-friendly spelling)")
	fs.StringVar(&c.UnsealKeyFile, "unseal-key-file", "", "file with unseal keys (one per line) to unseal at startup (convenience; protect this file)")
	fs.StringVar(&c.PublicURL, "public-url", "", "externally reachable API URL used in share links")
	fs.Parse(args)
	s, err := server.New(c)
	if err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	if !c.Dev {
		if !s.Core.Initialized() {
			log.Printf("Coffer is not initialized. Open http://%s:%d/ui/ or run: coffer operator init", c.IP, c.APIPort)
		} else if s.Core.Sealed() {
			log.Printf("Coffer is sealed. Unseal it in the UI or with: coffer operator unseal")
		}
	}
	waitForSignal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.Shutdown(ctx)
	return nil
}

func secretFlag(fs *flag.FlagSet) *string {
	return fs.String("cluster.secret", os.Getenv("COFFER_CLUSTER_SECRET"), "shared cluster secret (must match on all nodes)")
}

func runMaster(args []string) error {
	fs := flag.NewFlagSet("master", flag.ExitOnError)
	port := fs.Int("port", 9333, "listen port")
	bind := fs.String("bind", "0.0.0.0", "listen address")
	dir := fs.String("dir", "./coffer-master", "metadata directory")
	limit := fs.Int64("volumeSizeLimitMB", 1024, "volume size limit in MB")
	repl := fs.String("defaultReplication", "000", "default replication")
	secret := secretFlag(fs)
	fs.Parse(args)
	m, err := storage.NewMaster(*dir, *limit<<20, *repl, &storage.ClusterAuth{Secret: []byte(*secret)})
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	go m.RunMaintenance(stop)
	addr := fmt.Sprintf("%s:%d", *bind, *port)
	srv := &http.Server{Addr: addr, Handler: m.Handler(), ReadHeaderTimeout: 30 * time.Second}
	go func() {
		log.Printf("master listening on %s (replication default %s)", addr, *repl)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	waitForSignal()
	close(stop)
	srv.Shutdown(context.Background())
	return nil
}

func runVolume(args []string) error {
	fs := flag.NewFlagSet("volume", flag.ExitOnError)
	port := fs.Int("port", 8080, "listen port")
	bind := fs.String("bind", "0.0.0.0", "listen address")
	ip := fs.String("ip", "127.0.0.1", "address the master and clients use to reach this server")
	publicURL := fs.String("publicUrl", "", "public address (defaults to ip:port)")
	dir := fs.String("dir", "./coffer-volume", "data directory")
	master := fs.String("master", "127.0.0.1:9333", "comma separated master addresses")
	max := fs.Int("max", 16, "max number of volumes")
	dc := fs.String("dataCenter", "dc1", "data center name")
	rack := fs.String("rack", "rack1", "rack name")
	secret := secretFlag(fs)
	fs.Parse(args)
	st, err := storage.OpenStore(*dir, *max, 1024<<20)
	if err != nil {
		return err
	}
	vs := storage.NewVolumeServer(st, fmt.Sprintf("%s:%d", *ip, *port), *publicURL, strings.Split(*master, ","), *dc, *rack, &storage.ClusterAuth{Secret: []byte(*secret)})
	stop := make(chan struct{})
	go vs.RunHeartbeat(stop)
	addr := fmt.Sprintf("%s:%d", *bind, *port)
	srv := &http.Server{Addr: addr, Handler: vs.Handler(), ReadHeaderTimeout: 30 * time.Second}
	go func() {
		log.Printf("volume server listening on %s (dir %s, dc=%s rack=%s)", addr, filepath.Clean(*dir), *dc, *rack)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	waitForSignal()
	close(stop)
	srv.Shutdown(context.Background())
	st.Close()
	return nil
}
