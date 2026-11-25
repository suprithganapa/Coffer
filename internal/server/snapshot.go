package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"coffer/internal/kvstore"
	"coffer/internal/vault"
)

// Snapshot format:
//   COFFER-SNAPSHOT 1\n
//   section <name> <bytes> <sha256>\n<bytes of kvstore records>   (repeated)
// Secrets inside the "vault" section stay barrier-encrypted, so a snapshot
// is useless without a quorum of unseal keys. Blob data is not included:
// it lives on volume servers and is protected by replication.

const snapMagic = "COFFER-SNAPSHOT 1\n"

func writeSection(w io.Writer, name string, data []byte) error {
	sum := sha256.Sum256(data)
	if _, err := fmt.Fprintf(w, "section %s %d %s\n", name, len(data), hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// Snapshot builds a backup of secrets, file index and master state.
func (s *Server) Snapshot() ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(snapMagic)
	for i, name := range []string{"vault", "filer"} {
		var b bytes.Buffer
		if err := s.stores[i].Export(&b); err != nil {
			return nil, err
		}
		if err := writeSection(&out, name, b.Bytes()); err != nil {
			return nil, err
		}
	}
	if s.Master != nil {
		if b, err := os.ReadFile(filepath.Join(s.cfg.Dir, "master", "master.json")); err == nil {
			writeSection(&out, "master", b)
		}
	}
	return out.Bytes(), nil
}

func (s *Server) sysSnapshot(req *vault.Request) (*vault.Response, error) {
	if req.Operation != vault.OpRead {
		return nil, codeErr(405, "use GET to download a snapshot; restore is done offline with `coffer operator snapshot restore`")
	}
	data, err := s.Snapshot()
	if err != nil {
		return nil, err
	}
	return &vault.Response{Raw: &vault.RawResponse{Status: 200, ContentType: "application/octet-stream", Body: data}}, nil
}

// RestoreSnapshot restores a snapshot into dir. The server must be stopped.
func RestoreSnapshot(dir string, r io.Reader) ([]string, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(snapMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != snapMagic {
		return nil, errors.New("not a Coffer snapshot file")
	}
	sections := map[string][]byte{}
	for {
		line, err := br.ReadString('\n')
		if err == io.EOF && line == "" {
			break
		}
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != "section" {
			return nil, errors.New("snapshot is corrupt (bad section header)")
		}
		n, err := strconv.Atoi(f[2])
		if err != nil || n < 0 {
			return nil, errors.New("snapshot is corrupt (bad size)")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, errors.New("snapshot is truncated")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f[3] {
			return nil, fmt.Errorf("snapshot section %q failed its checksum", f[1])
		}
		sections[f[1]] = data
	}
	if sections["vault"] == nil || sections["filer"] == nil {
		return nil, errors.New("snapshot is missing required sections")
	}
	suffix := strconv.FormatInt(time.Now().Unix(), 10)
	var done []string
	for _, name := range []string{"vault", "filer"} {
		if err := kvRestore(filepath.Join(dir, name), sections[name], suffix); err != nil {
			return done, fmt.Errorf("restore %s: %w", name, err)
		}
		done = append(done, name)
	}
	if m := sections["master"]; m != nil {
		md := filepath.Join(dir, "master")
		os.MkdirAll(md, 0o755)
		p := filepath.Join(md, "master.json")
		if old, err := os.ReadFile(p); err == nil {
			os.WriteFile(p+".bak-"+suffix, old, 0o644)
		}
		if err := os.WriteFile(p, m, 0o644); err != nil {
			return done, err
		}
		done = append(done, "master")
	}
	return done, nil
}

func kvRestore(dir string, data []byte, suffix string) error {
	return kvstoreRestore(dir, bytes.NewReader(data), suffix)
}

var kvstoreRestore = kvstore.Restore
