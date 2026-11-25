package storage

import (
	"bytes"
	"testing"
)

func TestVolumeWriteReadDeleteCompact(t *testing.T) {
	dir := t.TempDir()
	v, err := OpenVolume(dir, "c", 7, ReplicaPlacement{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 50; i++ {
		if _, err := v.Write(&Needle{ID: i, Cookie: 42, Data: bytes.Repeat([]byte{byte(i)}, 1000), Name: "f"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Write(&Needle{ID: 3, Cookie: 99, Data: []byte("x")}); err != ErrCookie {
		t.Fatal("cookie overwrite must fail")
	}
	for i := uint64(1); i <= 40; i++ {
		v.Delete(i, 42)
	}
	if _, err := v.Read(5, 42); err != ErrNotFound {
		t.Fatal("deleted needle readable")
	}
	before := v.Info().Size
	if err := v.Compact(); err != nil {
		t.Fatal(err)
	}
	if after := v.Info().Size; after >= before/2 {
		t.Fatalf("compaction did not shrink: %d -> %d", before, after)
	}
	n, err := v.Read(45, 42)
	if err != nil || n.Data[0] != 45 || n.Name != "f" {
		t.Fatalf("survivor lost: %v", err)
	}
	v.Close()
	v2, _ := OpenVolume(dir, "c", 7, ReplicaPlacement{}, 0, 0)
	if v2.Info().FileCount != 10 {
		t.Fatalf("reload count %d", v2.Info().FileCount)
	}
}

func TestFileIDRoundTrip(t *testing.T) {
	f := FileID{VolumeID: 3, Key: 0x1637037, Cookie: 0xd6a0b1c2}
	g, err := ParseFileID(f.String())
	if err != nil || g != f {
		t.Fatalf("%v %v", g, err)
	}
	if _, err := ParseFileID("nope"); err == nil {
		t.Fatal("bad fid accepted")
	}
}
