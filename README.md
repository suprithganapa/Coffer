# Coffer

**Secrets and distributed storage behind one seal.**

Coffer is a single Go binary that combines a **secrets manager** (in the spirit of
[OpenBao](https://github.com/openbao/openbao)) with a **distributed file and object
store** (in the spirit of [SeaweedFS](https://github.com/seaweedfs/seaweedfs)), and
joins them where they meet: storage is encrypted with keys from the secrets engine,
one policy language governs secrets, files and S3, one audit trail records
everything, and one web console runs all of it.

When Coffer is **sealed**, nothing is readable: not the secrets, not encrypted files,
not S3 objects. Key holders unseal it together using Shamir key shares.

```
                 ┌─────────────── coffer server (gateway) ───────────────┐
  Browser ──────▶│  Web console  /ui                                     │
  coffer CLI ───▶│  HTTP API     /v1/...   (secrets, sys, auth)          │
  curl / SDKs ──▶│  Filer API    /v1/fs/... (files & folders)            │
  S3 clients ───▶│  S3 gateway   :8333     (SigV4)                       │
                 │        │ one ACL + audit │        │ envelope crypto    │
                 │  ┌─────▼──────────┐ ┌────▼───────▼────┐               │
                 │  │ Secrets core   │ │ Filer (metadata)│               │
                 │  │ barrier, Shamir│ │ chunks, folders │               │
                 │  └────────────────┘ └────────┬────────┘               │
                 └──────────────────────────────┼────────────────────────┘
                                                │ assign / lookup
                                   ┌────────────▼───────────┐
                                   │ Master (topology, fids)│
                                   └───┬─────────┬─────────┬┘
                                  ┌────▼───┐ ┌───▼────┐ ┌──▼─────┐
                                  │Volume 1│ │Volume 2│ │Volume N│  replicated
                                  └────────┘ └────────┘ └────────┘  needle files
```

## Features

| Area | What you get |
|---|---|
| **Seal & barrier** | Shamir unseal keys (N shares, threshold T), AES‑256‑GCM encrypted storage barrier, key rotation (terms), rekey, generate‑root, optional auto‑unseal file |
| **Auth** | Tokens (TTL, renew, revoke trees, use limits, orphans, accessors), username/password (PBKDF2, lockout), AppRole (role‑id + secret‑id, CIDR binding) |
| **Policies** | OpenBao/Vault style HCL or JSON: `create read update patch delete list sudo deny`, `*` and `+` globs, most‑specific‑wins, deny‑wins |
| **Secrets engines** | KV v2 (versions, soft delete, undelete, destroy, CAS, metadata), KV v1, Transit (AES‑GCM, Ed25519, ECDSA, HMAC, rotate, rewrap, data keys, derived keys, export, auto‑rotate), PKI (root CA, roles, issue, sign CSR, revoke, CRL), TOTP, Cubbyhole |
| **Response wrapping** | Wrap any response in a single‑use token (`X-Coffer-Wrap-TTL`) and unwrap it later |
| **Backup & DR** | One‑command encrypted snapshots (`coffer operator snapshot save/restore`, console button), checksummed, with a recovery runbook |
| **Audit** | Every secrets, file and S3 request; secret values HMAC'd with a cluster salt; file devices + live in‑memory feed |
| **Blob storage** | Master + volume servers, append‑only needle volumes, file ids with anti‑guessing cookies, rack/DC aware replication (`000`…`xyz`), automatic volume growth, compaction (vacuum), TTL volumes, signed intra‑cluster tokens |
| **Filer** | Folders and files, chunked large files, range reads, rename/move without copying, copy, recursive delete, per‑folder settings (encryption key, replication, TTL) inherited downward |
| **S3 gateway** | Buckets, Put/Get/Head/Delete, multi‑delete, ListObjects v1/v2 (prefix, delimiter, pagination), CopyObject, multipart (incl. UploadPartCopy), tagging, bucket encryption, SSE headers, presigned URLs, aws‑chunked streaming uploads, public‑read buckets |
| **Integration** | Envelope encryption of file chunks with transit keys, seal locks storage too, S3 keys carry ACL policies, share links for files, unified audit |
| **Console** | Init/unseal wizard, secrets browser & editors, transit/PKI/TOTP tools, file manager with drag‑and‑drop upload, buckets, cluster topology, policies, users, tokens, S3 keys, share links, audit log, system tools |

## Quick start (5 minutes)

Requirements: Go 1.24+ (no other dependencies — only the Go standard library is used).

```bash
make build                 # or: go build -o bin/coffer ./cmd/coffer
./bin/coffer server -dev -dev-root-token=root
```

Dev mode initializes with one unseal key, unseals automatically and prints:

```
Web UI:       http://127.0.0.1:8200/ui/
API address:  http://127.0.0.1:8200
S3 endpoint:  http://127.0.0.1:8333
Root token:   root
```

On Windows (PowerShell), build once with `go build -o bin\coffer.exe .\cmd\coffer`
(or use a prebuilt `bin\coffer.exe` from the release zip), then:

```powershell
.\bin\coffer.exe server -dev -dev-root-token=root
# in a second window
$env:COFFER_ADDR="http://127.0.0.1:8200"; $env:COFFER_TOKEN="root"
.\bin\coffer.exe kv put secret/hello msg=world
```

Open the web UI and sign in with the token `root`. Dev mode keeps data in
`./coffer-data` and auto‑unseals on restart — **never use it in production**
(see [Operations](docs/OPERATIONS.md) for a real deployment).

## A simple user flow

A team wants nightly database backups stored **encrypted**, written by a backup job
that can't read anything else, plus the database password kept as a secret.

```bash
export COFFER_ADDR=http://127.0.0.1:8200 COFFER_TOKEN=root

# 1. Store the database password as a versioned secret
coffer kv put secret/backups/db password='p@ss-2026' host=db.internal

# 2. A policy that only allows writing into one bucket and reading that secret
cat > backup.hcl <<'EOF'
path "fs/buckets/team-backups/*" { capabilities = ["create", "read", "list"] }
path "fs/buckets/team-backups"   { capabilities = ["read", "list"] }
path "secret/data/backups/db"    { capabilities = ["read"] }
EOF
coffer policy write backup-writer backup.hcl

# 3. Create the bucket and encrypt everything written to it with a transit key
coffer fs mkdir /buckets/team-backups
coffer fs encrypt -key=team-backups /buckets/team-backups

# 4. Give the job an S3 key bound to that policy (secret shown once)
coffer s3 keys-create -policy=backup-writer -description="nightly job"

# 5. The job uploads with any S3 client
aws --endpoint-url http://127.0.0.1:8333 s3 cp ./db-2026-11-25.dump s3://team-backups/2026-11-25/

# 6. Share a restore copy with a colleague for one day, one download
coffer fs share -ttl=24h -max-downloads=1 /buckets/team-backups/2026-11-25/db-2026-11-25.dump

# 7. Seal in an emergency: every secret, file and object becomes unreadable
coffer operator seal
```

The same flow is clickable in the console (Secrets → Access → Buckets → Files →
System). A longer walkthrough with screenshots of each step is in the
[User guide](docs/USER_GUIDE.md).

## Documentation

| Document | Contents |
|---|---|
| [User guide](docs/USER_GUIDE.md) | Console tour, end‑to‑end walkthrough, everyday tasks |
| [Architecture](docs/ARCHITECTURE.md) | How the pieces work: seal, barrier, tokens, ACL, volumes, filer, encryption, S3 |
| [Operations](docs/OPERATIONS.md) | Production install, multi‑node clusters, flags, TLS, backups, key ceremonies, monitoring |
| [API reference](docs/API.md) | HTTP endpoints for secrets, sys, files, S3, master and volume servers |
| [CLI reference](docs/CLI.md) | Every `coffer` command |

## Project layout

```
cmd/coffer/            CLI entry point: servers + client commands
internal/kvstore/      durable ordered KV store (WAL + snapshots, crash safe)
internal/shamir/       Shamir secret sharing over GF(256)
internal/vault/        secrets core: barrier, seal, tokens, policies, engines, audit
internal/storage/      needles, volumes, volume server, master, cluster auth, client
internal/filer/        namespace, chunking, envelope encryption, readers
internal/s3api/        S3 gateway and SigV4 verification
internal/server/       wires everything together, HTTP API, shares, S3 keys
internal/ui/static/    web console (vanilla JS, embedded in the binary)
docs/                  documentation
```

## Testing

```bash
make test     # vet + unit + integration tests
make race     # the same under the race detector
```

The integration suite starts real servers on random ports and drives them over
HTTP: S3 (signed with SigV4, verified against the AWS reference test vectors),
multipart uploads, encryption at rest (it checks that the volume server only holds
ciphertext), seal/unseal behaviour, policy enforcement, share links, rename and
recursive delete, audit coverage, vacuum, and cross‑server replication.

## Relationship to OpenBao and SeaweedFS

Coffer is a **new, independent implementation**. It reproduces the concepts and
wire formats people know from those projects (Vault‑style API paths and tokens,
SeaweedFS‑style file ids, volumes and replication codes), so existing knowledge and
many clients carry over. No code was copied from either project. Coffer does not
yet cover every feature of either upstream — see
[what is not included](docs/ARCHITECTURE.md#scope-what-coffer-does-not-include).
