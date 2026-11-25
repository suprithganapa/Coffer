// Package shamir implements Shamir's Secret Sharing over GF(2^8).
// Each share is len(secret)+1 bytes; the final byte is the x coordinate.
package shamir

import (
	"crypto/rand"
	"errors"
)

var expTable, logTable [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		// multiply by generator 3 in GF(2^8) with AES polynomial
		hi := x & 0x80
		x2 := x << 1
		if hi != 0 {
			x2 ^= 0x1b
		}
		x ^= x2
	}
	expTable[255] = expTable[0]
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[(int(logTable[a])+int(logTable[b]))%255]
}

func div(a, b byte) byte {
	if b == 0 {
		panic("divide by zero")
	}
	if a == 0 {
		return 0
	}
	return expTable[(int(logTable[a])-int(logTable[b])+255)%255]
}

// Split divides secret into parts shares, any threshold of which recover it.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if parts < threshold {
		return nil, errors.New("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, errors.New("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split an empty secret")
	}
	out := make([][]byte, parts)
	for i := range out {
		out[i] = make([]byte, len(secret)+1)
		out[i][len(secret)] = byte(i + 1)
	}
	coeffs := make([]byte, threshold)
	for idx, b := range secret {
		coeffs[0] = b
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for i := 0; i < parts; i++ {
			x := byte(i + 1)
			// Horner evaluation
			var y byte
			for j := threshold - 1; j >= 0; j-- {
				y = mul(y, x) ^ coeffs[j]
			}
			out[i][idx] = y
		}
	}
	return out, nil
}

// Combine recovers the secret from shares (at least threshold of them).
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("less than two shares cannot be used to reconstruct the secret")
	}
	l := len(shares[0])
	if l < 2 {
		return nil, errors.New("shares must be at least two bytes")
	}
	xs := make([]byte, len(shares))
	seen := map[byte]bool{}
	for i, s := range shares {
		if len(s) != l {
			return nil, errors.New("all shares must be the same length")
		}
		xs[i] = s[l-1]
		if seen[xs[i]] {
			return nil, errors.New("duplicate share detected")
		}
		seen[xs[i]] = true
	}
	secret := make([]byte, l-1)
	for idx := range secret {
		var acc byte
		for i := range shares {
			// Lagrange basis at x=0
			num, den := byte(1), byte(1)
			for j := range shares {
				if i == j {
					continue
				}
				num = mul(num, xs[j])
				den = mul(den, xs[i]^xs[j])
			}
			acc ^= mul(shares[i][idx], div(num, den))
		}
		secret[idx] = acc
	}
	return secret, nil
}
