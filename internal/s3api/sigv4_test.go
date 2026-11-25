package s3api

import (
	"net/http"
	"testing"
)

const (
	exAK     = "AKIAIOSFODNN7EXAMPLE"
	exSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// Test vectors from the AWS Signature Version 4 documentation for S3.
func TestSigV4HeaderVector(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Host = "examplebucket.s3.amazonaws.com"
	r.Header.Set("Range", "bytes=0-9")
	r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	s := &sigV4{AccessKey: exAK, Date: "20130524", Region: "us-east-1", Service: "s3", AmzDate: "20130524T000000Z",
		SignedHeaders: []string{"host", "range", "x-amz-content-sha256", "x-amz-date"}}
	got := computeSignature(exSecret, s, buildCanonicalRequest(r, s))
	want := "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got != want {
		t.Fatalf("signature mismatch\n got %s\nwant %s\ncanonical:\n%s", got, want, buildCanonicalRequest(r, s))
	}
}

func TestSigV4PresignedVector(t *testing.T) {
	u := "http://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	r, _ := http.NewRequest("GET", u, nil)
	r.Host = "examplebucket.s3.amazonaws.com"
	s, err := parseSigV4(r)
	if err != nil || s == nil || !s.Presigned {
		t.Fatalf("parse: %v %+v", err, s)
	}
	got := computeSignature(exSecret, s, buildCanonicalRequest(r, s))
	if got != s.Signature {
		t.Fatalf("presigned mismatch: got %s want %s", got, s.Signature)
	}
}

func TestParseAuthHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://h/b/k", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AK/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	r.Header.Set("X-Amz-Date", "20240101T000000Z")
	s, err := parseSigV4(r)
	if err != nil {
		t.Fatal(err)
	}
	if s.AccessKey != "AK" || len(s.SignedHeaders) != 2 || s.Signature != "abc" {
		t.Fatalf("%+v", s)
	}
}
