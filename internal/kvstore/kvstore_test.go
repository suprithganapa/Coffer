package kvstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistenceAndTornTail(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for i := 0; i < 100; i++ {
		s.Put(fmt.Sprintf("a/%03d", i), []byte{byte(i)})
	}
	s.Delete("a/050")
	s.Put("a/b/c", []byte("x"))
	s.Close()
	// simulate a crash mid-write: append garbage
	f, _ := os.OpenFile(filepath.Join(dir, "wal.log"), os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{1, 0, 0, 0, 9, 0})
	f.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 100 {
		t.Fatalf("len %d", s2.Len())
	}
	if _, ok := s2.Get("a/050"); ok {
		t.Fatal("deleted key resurrected")
	}
	ls := s2.List("a/")
	if ls[len(ls)-1] != "b/" {
		t.Fatalf("list %v", ls[len(ls)-3:])
	}
	if err := s2.Put("after", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	s2.Close()
	s3, _ := Open(dir)
	if v, ok := s3.Get("after"); !ok || string(v) != "ok" {
		t.Fatal("write after torn-tail recovery lost")
	}
}

func TestCompaction(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for i := 0; i < compactEvery+500; i++ {
		s.Put(fmt.Sprintf("k%d", i%1000), []byte(fmt.Sprint(i)))
	}
	s.Close()
	s2, _ := Open(dir)
	if s2.Len() != 1000 {
		t.Fatalf("len %d", s2.Len())
	}
	if v, _ := s2.Get("k999"); len(v) == 0 {
		t.Fatal("missing after compaction")
	}
}
