package vault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// pkiBackend is an X.509 certificate authority.
type pkiBackend struct {
	view  *View
	mount *MountEntry
	mu    sync.Mutex
}

type pkiCA struct {
	CertPEM string `json:"certificate"`
	KeyPEM  string `json:"private_key"`
	Serial  string `json:"serial_number"`
}

type pkiRole struct {
	AllowedDomains   []string      `json:"allowed_domains"`
	AllowSubdomains  bool          `json:"allow_subdomains"`
	AllowBareDomains bool          `json:"allow_bare_domains"`
	AllowAnyName     bool          `json:"allow_any_name"`
	AllowLocalhost   bool          `json:"allow_localhost"`
	AllowIPSANs      bool          `json:"allow_ip_sans"`
	ServerFlag       bool          `json:"server_flag"`
	ClientFlag       bool          `json:"client_flag"`
	KeyType          string        `json:"key_type"`
	KeyBits          int           `json:"key_bits"`
	TTL              time.Duration `json:"ttl"`
	MaxTTL           time.Duration `json:"max_ttl"`
	Organization     []string      `json:"organization"`
}

type pkiCert struct {
	PEM            string     `json:"certificate"`
	Serial         string     `json:"serial_number"`
	CommonName     string     `json:"common_name"`
	NotAfter       time.Time  `json:"expiration"`
	RevocationTime *time.Time `json:"revocation_time"`
	Role           string     `json:"role"`
}

func (b *pkiBackend) UnauthenticatedPaths() []string {
	return []string{"ca", "ca/pem", "crl", "crl/pem", "cert/*"}
}

func (b *pkiBackend) Exists(req *Request) (bool, error) {
	if strings.HasPrefix(req.RelPath, "roles/") {
		v, err := b.view.Get("role/" + strings.TrimPrefix(req.RelPath, "roles/"))
		return v != nil, err
	}
	return true, nil
}

func serialString(n *big.Int) string {
	h := hex.EncodeToString(n.Bytes())
	var parts []string
	for i := 0; i < len(h); i += 2 {
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, ":")
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func genKey(typ string, bits int) (crypto.Signer, string, error) {
	switch typ {
	case "", "ec":
		curve := elliptic.P256()
		if bits == 384 {
			curve = elliptic.P384()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, _ := x509.MarshalECPrivateKey(k)
		return k, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
	case "rsa":
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, "", badRequest("rsa keys must be at least 2048 bits")
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, "", err
		}
		der := x509.MarshalPKCS1PrivateKey(k)
		return k, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})), nil
	}
	return nil, "", badRequest("unsupported key_type %q (ec or rsa)", typ)
}

func parseKeyPEM(s string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, badRequest("invalid key PEM")
	}
	switch blk.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(crypto.Signer), nil
}

func (b *pkiBackend) loadCA() (*pkiCA, *x509.Certificate, crypto.Signer, error) {
	var ca pkiCA
	ok, err := b.view.GetJSON("ca", &ca)
	if err != nil {
		return nil, nil, nil, err
	}
	if !ok {
		return nil, nil, nil, badRequest("no CA configured: generate one with root/generate/internal")
	}
	blk, _ := pem.Decode([]byte(ca.CertPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := parseKeyPEM(ca.KeyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	return &ca, cert, key, nil
}

func skid(pub crypto.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha1.Sum(der)
	return h[:]
}

func (b *pkiBackend) Handle(req *Request) (*Response, error) {
	rel := strings.Trim(req.RelPath, "/")
	d := req.Data
	switch {
	case rel == "root/generate/internal" || rel == "root/generate/exported":
		return b.generateRoot(d, rel == "root/generate/exported")
	case rel == "root" && req.Operation == OpDelete:
		b.view.Delete("ca")
		b.view.Delete("crl")
		return &Response{StatusCode: 204}, nil
	case rel == "ca/pem" || rel == "ca":
		ca, _, _, err := b.loadCA()
		if err != nil {
			return nil, err
		}
		if rel == "ca" {
			blk, _ := pem.Decode([]byte(ca.CertPEM))
			return &Response{Raw: &RawResponse{Status: 200, ContentType: "application/pkix-cert", Body: blk.Bytes}}, nil
		}
		return &Response{Raw: &RawResponse{Status: 200, ContentType: "application/pem-certificate-chain", Body: []byte(ca.CertPEM)}}, nil
	case rel == "cert/ca":
		ca, _, _, err := b.loadCA()
		if err != nil {
			return nil, err
		}
		return &Response{Data: map[string]any{"certificate": ca.CertPEM, "serial_number": ca.Serial}}, nil
	case rel == "crl" || rel == "crl/pem":
		crl, err := b.view.Get("crl")
		if err != nil {
			return nil, err
		}
		if crl == nil {
			if crl, err = b.buildCRL(); err != nil {
				return nil, err
			}
		}
		if rel == "crl" {
			return &Response{Raw: &RawResponse{Status: 200, ContentType: "application/pkix-crl", Body: crl}}, nil
		}
		return &Response{Raw: &RawResponse{Status: 200, ContentType: "application/x-pem-file", Body: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})}}, nil
	case rel == "crl/rotate":
		if _, err := b.buildCRL(); err != nil {
			return nil, err
		}
		return &Response{Data: map[string]any{"success": true}}, nil
	case rel == "roles" || rel == "roles/":
		keys, err := b.view.List("role/")
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	case strings.HasPrefix(rel, "roles/"):
		return b.handleRole(req, strings.TrimPrefix(rel, "roles/"))
	case strings.HasPrefix(rel, "issue/"):
		return b.issue(strings.TrimPrefix(rel, "issue/"), d, nil)
	case strings.HasPrefix(rel, "sign/"):
		csrPEM := dString(d, "csr")
		blk, _ := pem.Decode([]byte(csrPEM))
		if blk == nil {
			return nil, badRequest("csr must be PEM encoded")
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			return nil, badRequest("invalid csr: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, badRequest("csr signature invalid")
		}
		return b.issue(strings.TrimPrefix(rel, "sign/"), d, csr)
	case rel == "certs" || rel == "certs/":
		keys, err := b.view.List("cert/")
		if err != nil {
			return nil, err
		}
		return listResponse(keys), nil
	case strings.HasPrefix(rel, "cert/"):
		var c pkiCert
		ok, err := b.view.GetJSON("cert/"+strings.TrimPrefix(rel, "cert/"), &c)
		if err != nil || !ok {
			return nil, err
		}
		return &Response{Data: toMap(c)}, nil
	case rel == "revoke":
		return b.revoke(dString(d, "serial_number"))
	}
	return nil, errCode(404, "unsupported pki path %q", rel)
}

func (b *pkiBackend) generateRoot(d map[string]any, exported bool) (*Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, _ := b.view.Get("ca"); v != nil {
		return nil, badRequest("a CA already exists on this mount; DELETE %sroot first", b.mount.Path)
	}
	cn := dString(d, "common_name")
	if cn == "" {
		return nil, badRequest("common_name is required")
	}
	ttl, err := dDuration(d, "ttl", 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	key, keyPEM, err := genKey(dString(d, "key_type"), dInt(d, "key_bits", 0))
	if err != nil {
		return nil, err
	}
	serial := randomSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: dStrings(d, "organization")},
		NotBefore:    time.Now().Add(-30 * time.Second), NotAfter: time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, SubjectKeyId: skid(key.Public()),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	ca := pkiCA{CertPEM: certPEM, KeyPEM: keyPEM, Serial: serialString(serial)}
	if err := b.view.PutJSON("ca", ca); err != nil {
		return nil, err
	}
	b.view.Delete("crl")
	out := map[string]any{"certificate": certPEM, "issuing_ca": certPEM, "serial_number": ca.Serial, "expiration": tmpl.NotAfter.Unix()}
	if exported {
		out["private_key"] = keyPEM
	}
	return &Response{Data: out}, nil
}

func (b *pkiBackend) handleRole(req *Request, name string) (*Response, error) {
	switch req.Operation {
	case OpRead:
		var r pkiRole
		ok, err := b.view.GetJSON("role/"+name, &r)
		if err != nil || !ok {
			return nil, err
		}
		m := toMap(r)
		m["ttl"] = int(r.TTL.Seconds())
		m["max_ttl"] = int(r.MaxTTL.Seconds())
		return &Response{Data: m}, nil
	case OpDelete:
		return &Response{StatusCode: 204}, b.view.Delete("role/" + name)
	case OpCreate, OpUpdate:
		d := req.Data
		var r pkiRole
		b.view.GetJSON("role/"+name, &r)
		if req.Operation == OpCreate {
			r = pkiRole{ServerFlag: true, ClientFlag: true, AllowLocalhost: true, AllowIPSANs: true, KeyType: "ec"}
		}
		if has(d, "allowed_domains") {
			r.AllowedDomains = dStrings(d, "allowed_domains")
		}
		for k, p := range map[string]*bool{"allow_subdomains": &r.AllowSubdomains, "allow_bare_domains": &r.AllowBareDomains, "allow_any_name": &r.AllowAnyName, "allow_localhost": &r.AllowLocalhost, "allow_ip_sans": &r.AllowIPSANs, "server_flag": &r.ServerFlag, "client_flag": &r.ClientFlag} {
			if has(d, k) {
				*p = dBool(d, k, *p)
			}
		}
		if has(d, "key_type") {
			r.KeyType = dString(d, "key_type")
		}
		if has(d, "key_bits") {
			r.KeyBits = dInt(d, "key_bits", 0)
		}
		if has(d, "organization") {
			r.Organization = dStrings(d, "organization")
		}
		var err error
		if r.TTL, err = dDuration(d, "ttl", r.TTL); err != nil {
			return nil, err
		}
		if r.MaxTTL, err = dDuration(d, "max_ttl", r.MaxTTL); err != nil {
			return nil, err
		}
		if _, _, err := genKeyCheck(r.KeyType); err != nil {
			return nil, err
		}
		return &Response{StatusCode: 204}, b.view.PutJSON("role/"+name, r)
	}
	return nil, badRequest("unsupported operation")
}

func genKeyCheck(t string) (string, int, error) {
	if t == "" || t == "ec" || t == "rsa" {
		return t, 0, nil
	}
	return "", 0, badRequest("key_type must be ec or rsa")
}

func (r *pkiRole) nameAllowed(name string) bool {
	if r.AllowAnyName {
		return true
	}
	if r.AllowLocalhost && (name == "localhost" || name == "localdomain") {
		return true
	}
	for _, d := range r.AllowedDomains {
		if strings.HasPrefix(d, "*.") {
			if strings.HasSuffix(name, d[1:]) && !strings.Contains(strings.TrimSuffix(name, d[1:]), ".") {
				return true
			}
			continue
		}
		if name == d && r.AllowBareDomains {
			return true
		}
		if r.AllowSubdomains && strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (b *pkiBackend) issue(roleName string, d map[string]any, csr *x509.CertificateRequest) (*Response, error) {
	var role pkiRole
	ok, err := b.view.GetJSON("role/"+roleName, &role)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, badRequest("unknown role %q", roleName)
	}
	ca, caCert, caKey, err := b.loadCA()
	if err != nil {
		return nil, err
	}
	cn := dString(d, "common_name")
	if cn == "" && csr != nil {
		cn = csr.Subject.CommonName
	}
	if cn == "" {
		return nil, badRequest("common_name is required")
	}
	names := []string{cn}
	names = append(names, dStrings(d, "alt_names")...)
	if csr != nil {
		names = append(names, csr.DNSNames...)
	}
	var dns []string
	var ips []net.IP
	for _, n := range uniqSorted(names) {
		if ip := net.ParseIP(n); ip != nil {
			if !role.AllowIPSANs {
				return nil, badRequest("IP SANs are not allowed by role %q", roleName)
			}
			ips = append(ips, ip)
			continue
		}
		if !role.nameAllowed(n) {
			return nil, badRequest("name %q is not allowed by role %q", n, roleName)
		}
		dns = append(dns, n)
	}
	for _, s := range dStrings(d, "ip_sans") {
		ip := net.ParseIP(s)
		if ip == nil || !role.AllowIPSANs {
			return nil, badRequest("invalid or disallowed IP SAN %q", s)
		}
		ips = append(ips, ip)
	}
	ttl, err := dDuration(d, "ttl", role.TTL)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	if role.MaxTTL > 0 && ttl > role.MaxTTL {
		ttl = role.MaxTTL
	}
	notAfter := time.Now().Add(ttl)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	var pub crypto.PublicKey
	var keyPEM string
	if csr != nil {
		pub = csr.PublicKey
	} else {
		k, kp, err := genKey(role.KeyType, role.KeyBits)
		if err != nil {
			return nil, err
		}
		pub, keyPEM = k.Public(), kp
	}
	serial := randomSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: role.Organization},
		DNSNames:     dns, IPAddresses: ips,
		NotBefore: time.Now().Add(-30 * time.Second), NotAfter: notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		AuthorityKeyId: caCert.SubjectKeyId, SubjectKeyId: skid(pub),
	}
	if role.ServerFlag {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if role.ClientFlag {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sn := serialString(serial)
	if err := b.view.PutJSON("cert/"+sn, pkiCert{PEM: certPEM, Serial: sn, CommonName: cn, NotAfter: notAfter, Role: roleName}); err != nil {
		return nil, err
	}
	out := map[string]any{
		"certificate": certPEM, "issuing_ca": ca.CertPEM, "ca_chain": []string{ca.CertPEM},
		"serial_number": sn, "expiration": notAfter.Unix(),
	}
	if keyPEM != "" {
		out["private_key"] = keyPEM
		out["private_key_type"] = map[string]string{"": "ec", "ec": "ec", "rsa": "rsa"}[role.KeyType]
	}
	return &Response{Data: out}, nil
}

func (b *pkiBackend) revoke(serial string) (*Response, error) {
	if serial == "" {
		return nil, badRequest("serial_number is required")
	}
	var c pkiCert
	ok, err := b.view.GetJSON("cert/"+serial, &c)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, badRequest("certificate with serial %s not found", serial)
	}
	if c.RevocationTime == nil {
		t := now()
		c.RevocationTime = &t
		if err := b.view.PutJSON("cert/"+serial, c); err != nil {
			return nil, err
		}
	}
	if _, err := b.buildCRL(); err != nil {
		return nil, err
	}
	return &Response{Data: map[string]any{"revocation_time": c.RevocationTime.Unix()}}, nil
}

func (b *pkiBackend) buildCRL() ([]byte, error) {
	_, caCert, caKey, err := b.loadCA()
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	keys := b.view.Keys("cert/")
	sort.Strings(keys)
	for _, k := range keys {
		var c pkiCert
		if ok, _ := b.view.GetJSON(k, &c); ok && c.RevocationTime != nil {
			sn, _ := new(big.Int).SetString(strings.ReplaceAll(c.Serial, ":", ""), 16)
			entries = append(entries, x509.RevocationListEntry{SerialNumber: sn, RevocationTime: *c.RevocationTime})
		}
	}
	var num int64
	b.view.GetJSON("crl-number", &num)
	b.view.PutJSON("crl-number", num+1)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(num + 1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(72 * time.Hour),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return der, b.view.Put("crl", der)
}
