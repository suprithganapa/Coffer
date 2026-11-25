// Package storage implements Coffer's blob storage layer: append-only volume
// files of "needles" (SeaweedFS-style), volume servers, and the master that
// assigns file ids and tracks cluster topology.
package storage

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
)

const (
	NeedleHeaderSize = 16 // cookie(4) + id(8) + size(4)
	NeedleAlign      = 8
	TombstoneSize    = 0xFFFFFFFF
	SuperBlockSize   = 8
	IdxEntrySize     = 16
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// FileID identifies a blob: "<volumeId>,<needleId hex><cookie 8 hex>".
type FileID struct {
	VolumeID uint32
	Key      uint64
	Cookie   uint32
}

func (f FileID) String() string {
	return fmt.Sprintf("%d,%x%08x", f.VolumeID, f.Key, f.Cookie)
}

// ParseFileID parses "3,01637037d6" style ids.
func ParseFileID(s string) (FileID, error) {
	var f FileID
	s = strings.TrimPrefix(s, "/")
	if i := strings.IndexAny(s, "./?"); i > 0 { // allow extension
		s = s[:i]
	}
	comma := strings.IndexByte(s, ',')
	if comma <= 0 {
		return f, errors.New("invalid file id")
	}
	vid, err := strconv.ParseUint(s[:comma], 10, 32)
	if err != nil {
		return f, errors.New("invalid volume id")
	}
	rest := s[comma+1:]
	if len(rest) <= 8 || len(rest) > 24 {
		return f, errors.New("invalid needle id")
	}
	key, err := strconv.ParseUint(rest[:len(rest)-8], 16, 64)
	if err != nil {
		return f, errors.New("invalid needle key")
	}
	ck, err := strconv.ParseUint(rest[len(rest)-8:], 16, 32)
	if err != nil {
		return f, errors.New("invalid cookie")
	}
	return FileID{VolumeID: uint32(vid), Key: key, Cookie: uint32(ck)}, nil
}

// RandomCookie returns a random 32-bit cookie (prevents fid guessing).
func RandomCookie() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// Needle is a stored blob plus metadata.
type Needle struct {
	Cookie       uint32
	ID           uint64
	Data         []byte
	Name         string
	Mime         string
	LastModified uint64 // unix seconds
	TTLSeconds   uint32 // 0 = forever
}

// Body layout after header:
//
//	dataLen(4) data nameLen(1) name mimeLen(1) mime lastModified(8) ttl(4) crc(4) padding
func (n *Needle) bodySize() int {
	return 4 + len(n.Data) + 1 + len(n.Name) + 1 + len(n.Mime) + 8 + 4
}

// Encode serializes the needle including padding.
func (n *Needle) Encode() []byte {
	if len(n.Name) > 255 {
		n.Name = n.Name[:255]
	}
	if len(n.Mime) > 255 {
		n.Mime = n.Mime[:255]
	}
	body := n.bodySize()
	total := NeedleHeaderSize + body + 4
	if pad := total % NeedleAlign; pad != 0 {
		total += NeedleAlign - pad
	}
	b := make([]byte, total)
	binary.BigEndian.PutUint32(b[0:4], n.Cookie)
	binary.BigEndian.PutUint64(b[4:12], n.ID)
	binary.BigEndian.PutUint32(b[12:16], uint32(body))
	p := 16
	binary.BigEndian.PutUint32(b[p:], uint32(len(n.Data)))
	p += 4
	p += copy(b[p:], n.Data)
	b[p] = byte(len(n.Name))
	p++
	p += copy(b[p:], n.Name)
	b[p] = byte(len(n.Mime))
	p++
	p += copy(b[p:], n.Mime)
	binary.BigEndian.PutUint64(b[p:], n.LastModified)
	p += 8
	binary.BigEndian.PutUint32(b[p:], n.TTLSeconds)
	p += 4
	binary.BigEndian.PutUint32(b[p:], crc32.Checksum(n.Data, crcTable))
	return b
}

// DecodeNeedle parses a full needle record (header+body+crc).
func DecodeNeedle(b []byte) (*Needle, error) {
	if len(b) < NeedleHeaderSize {
		return nil, errors.New("needle too short")
	}
	n := &Needle{
		Cookie: binary.BigEndian.Uint32(b[0:4]),
		ID:     binary.BigEndian.Uint64(b[4:12]),
	}
	body := int(binary.BigEndian.Uint32(b[12:16]))
	if len(b) < NeedleHeaderSize+body+4 {
		return nil, errors.New("needle truncated")
	}
	p := 16
	dl := int(binary.BigEndian.Uint32(b[p:]))
	p += 4
	if p+dl > 16+body {
		return nil, errors.New("needle corrupt")
	}
	n.Data = b[p : p+dl]
	p += dl
	nl := int(b[p])
	p++
	n.Name = string(b[p : p+nl])
	p += nl
	ml := int(b[p])
	p++
	n.Mime = string(b[p : p+ml])
	p += ml
	n.LastModified = binary.BigEndian.Uint64(b[p:])
	p += 8
	n.TTLSeconds = binary.BigEndian.Uint32(b[p:])
	p += 4
	crc := binary.BigEndian.Uint32(b[p:])
	if crc32.Checksum(n.Data, crcTable) != crc {
		return nil, errors.New("needle checksum mismatch")
	}
	return n, nil
}

// ETag is the hex CRC of the data.
func (n *Needle) ETag() string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crc32.Checksum(n.Data, crcTable))
	return hex.EncodeToString(b[:])
}

// ReplicaPlacement is SeaweedFS's "xyz" notation:
// x = copies in other data centers, y = other racks in same DC,
// z = other servers in same rack.
type ReplicaPlacement struct {
	DiffDC, DiffRack, SameRack int
}

func ParseReplication(s string) (ReplicaPlacement, error) {
	if s == "" {
		s = "000"
	}
	if len(s) != 3 {
		return ReplicaPlacement{}, errors.New("replication must be 3 digits, e.g. 001")
	}
	var r ReplicaPlacement
	for i, c := range s {
		if c < '0' || c > '9' {
			return r, errors.New("replication must be 3 digits")
		}
		v := int(c - '0')
		switch i {
		case 0:
			r.DiffDC = v
		case 1:
			r.DiffRack = v
		case 2:
			r.SameRack = v
		}
	}
	return r, nil
}

func (r ReplicaPlacement) String() string {
	return fmt.Sprintf("%d%d%d", r.DiffDC, r.DiffRack, r.SameRack)
}

// Copies is the total number of replicas.
func (r ReplicaPlacement) Copies() int { return 1 + r.DiffDC + r.DiffRack + r.SameRack }

func (r ReplicaPlacement) Byte() byte { return byte(r.DiffDC*100 + r.DiffRack*10 + r.SameRack) }

func ReplicationFromByte(b byte) ReplicaPlacement {
	v := int(b)
	return ReplicaPlacement{DiffDC: v / 100, DiffRack: (v / 10) % 10, SameRack: v % 10}
}
