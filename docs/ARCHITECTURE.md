# How Coffer works

Coffer has two halves: a **secrets core** that is sealed and unsealed by people
holding key shares, and a **storage layer** that spreads file data across volume
servers. A **gateway** (the `coffer server` process) puts both behind one API,
one policy engine, one audit log and one console.

```
 clients ─▶ API /v1 ──▶ Core.HandleRequest ──▶ token ▶ ACL ▶ router ▶ engine ─▶ barrier ─▶ kvstore
         ─▶ /v1/fs  ──▶ token ▶ ACL(fs/…) ──▶ Filer ─▶ chunks ─▶ master assign ─▶ volume servers
         ─▶ S3 :8333 ─▶ SigV4 ▶ key policies ▶ Filer (same as above)
                                     │
                                     └─▶ Transit data keys (envelope encryption, needs unsealed core)
```

## 1. The seal and the barrier

* At **initialization** Coffer generates a random 256‑bit *root key* and splits it
  with Shamir's Secret Sharing over GF(2⁸) into *N* shares with threshold *T*
  (`internal/shamir`). Any *T* shares reconstruct the key; *T−1* shares reveal
  nothing.
* The root key encrypts the **keyring** (`core/keyring`). The keyring holds one or
  more *terms*: AES‑256 keys used by the **barrier**.
* Everything the core stores goes through the barrier
  (`internal/vault/barrier.go`): each value is sealed with AES‑256‑GCM, with a fresh
  nonce, the active term number in the header, and the **storage path as
  additional authenticated data**, so ciphertexts cannot be swapped between keys.
* **Unsealing** collects shares in memory until the threshold is met, rebuilds the
  root key, decrypts the keyring and keeps it only in RAM. **Sealing** wipes it.
  Wrong shares fail authentication and reset progress.
* `sys/rotate` adds a new term (new writes use it, old data stays readable).
  `sys/rekey` re‑splits a new root key into new shares. `sys/generate-root` mints a
  fresh root token from a quorum of shares.

The physical store (`internal/kvstore`) is an ordered in‑memory index persisted by
an append‑only write‑ahead log with CRC‑protected records, periodically compacted
into a snapshot. A torn record at the end of the log (power loss) is detected and
dropped on restart.

## 2. Requests, tokens and policies

Every API call becomes a `vault.Request` and passes through `Core.HandleRequest`:

1. **Seal check** – only `sys/init`, `sys/unseal`, `sys/seal-status`,
   `sys/health`, `sys/leader` and `sys/generate-root` work while sealed.
2. **Token lookup** – tokens look like `cof.<24 chars>` and are stored under their
   SHA‑256, so a storage dump never contains usable tokens. Each token has an
   accessor, policies, TTL, explicit max TTL, optional use limit and a parent.
   Revoking a token revokes its whole subtree, and children never outlive parents.
   Expired tokens are swept every 5 seconds through an expiry index.
3. **Authorization** – policies are merged into an ACL. The capability needed is
   derived from the operation (`read`, `list`, `delete`, `patch`, and `create` vs
   `update` decided by asking the engine whether the target exists). The most
   specific matching path wins (exact > fewer wildcards > longer), and `deny`
   always wins. Paths like `sys/audit`, `sys/rotate`, `sys/seal` also require
   `sudo`.
4. **Routing** – longest‑prefix match on the mount table to an engine
   (`secret/` → KV v2, `transit/`, `pki/`, `cubbyhole/`, …) or auth method
   (`auth/userpass/`, `auth/approle/`, `auth/token/`). Each mount gets its own
   barrier view (`logical/<uuid>/…`), so engines cannot read each other's data.
5. **Login responses** from auth methods are turned into real tokens by the core
   (auth methods can never mint root tokens).
6. **Response wrapping** – if `X-Coffer-Wrap-TTL` is set, the response is stored in
   the cubbyhole of a new single‑use token and only that token is returned.
7. **Audit** – request and response are recorded with string values replaced by
   `hmac-sha256:<hex>` using a per‑cluster salt kept in the barrier.

### Why one policy language covers files and S3

The filer API and the S3 gateway do not have their own permission systems. They ask
the core: *does this token have capability X on path `fs/<file path>`?* A bucket is
just the folder `/buckets/<name>`, so `fs/buckets/photos/*` governs the `photos`
bucket for the console, the filer API and S3 alike. An S3 access key is stored in
the barrier together with a list of policies; requests signed with it are evaluated
exactly like a token holding those policies. Creating a key requires holding every
policy you attach (no privilege escalation).

## 3. Blob storage

### Volumes and needles

A **volume** is a pair of files on a volume server
(`internal/storage/volume.go`):

* `<collection>_<id>.dat` – an 8‑byte superblock (version, replication, compaction
  revision, TTL) followed by **needles**. A needle is: cookie (4), key (8), body
  size (4), data length, data, name, MIME type, last‑modified, TTL, CRC‑32C of the
  data, padding to 8 bytes.
* `<collection>_<id>.idx` – 16‑byte entries `key, offset/8, length`; a length of
  `0xFFFFFFFF` is a tombstone. The in‑memory needle map is rebuilt from the index on
  start.

Writes append; deletes append a tombstone; overwrites with a different cookie are
rejected. **Compaction** copies live, unexpired needles into `.cpd/.cpx` files,
replays any writes that arrived during the copy, then swaps the files atomically.

A **file id** looks like `3,01637037d6`: volume id, needle key in hex, then an
8‑hex‑digit random cookie, so ids cannot be guessed.

### Master

The master (`internal/storage/master.go`) keeps the topology
(data center → rack → node) from **heartbeats** sent every 3 s by volume servers,
marks a node dead after 12 s of silence, and:

* **assigns** file ids: picks a writable volume for the requested
  `collection + replication + TTL`, hands out a key from a persisted sequence
  (reserved in batches of 10,000 so a crash never reuses ids) and a random cookie;
* **grows** volumes when none are writable, choosing nodes that satisfy the
  replication code;
* **vacuums** volumes whose garbage ratio exceeds a threshold (every 15 minutes and
  on demand);
* **deletes collections** (used to drop a whole bucket instantly).

Replication codes follow the familiar `xyz` form:

| Code | Copies | Placement |
|---|---|---|
| `000` | 1 | anywhere |
| `001` | 2 | two servers in the same rack |
| `010` | 2 | two racks in the same data center |
| `100` | 2 | two data centers |
| `011` | 3 | two in one rack, one in another rack |

A write goes to one replica, which forwards it to the others and only reports
success when all copies are stored. Reads try each replica in turn, so data stays
readable when a server is down.

### Cluster authentication

When a cluster secret is set (`-cluster.secret` or `COFFER_CLUSTER_SECRET`; the
all‑in‑one server generates one automatically), every master and volume endpoint
requires an HMAC‑SHA256 token: the master signs a short‑lived token scoped to each
assigned file id, and admin calls use a token scoped to `*`. Without the secret,
nobody can read, write or delete blobs directly, even if they can reach the ports.

## 4. Filer

The filer (`internal/filer`) gives the blobs a namespace. Each entry (file or
folder) is a JSON record keyed by `parent-dir \0 name` in its own kvstore, which
makes listing a folder a single ordered range scan.

* Files are split into **chunks** (4 MB by default). Each chunk is one blob. The
  entry stores chunk file ids, offsets, sizes and MD5s.
* Files under `/buckets/<name>/` are written to a **collection** named after the
  bucket, so deleting a bucket removes its volumes in one step.
* **Rename/move** only rewrites metadata. Overwriting a file frees the chunks the new
  version doesn't reuse, in the background.
* **Readers** implement `io.ReadSeeker` over the chunk list, so HTTP range
  requests, conditional GETs and resumable downloads work through standard library
  `http.ServeContent`.
* **Folder settings** (`DirConfig`) – encryption key, replication, TTL – are
  inherited by everything below the folder. `-` as the key name switches encryption
  off for a subtree.

### Envelope encryption

When a folder (or bucket) has an encryption key:

1. For each uploaded file the filer asks the transit engine for a new random 256‑bit
   **data key**, receiving it in plaintext and wrapped (`coffer:v<N>:…`) by the
   folder's transit key.
2. Each chunk is encrypted with AES‑256‑GCM under the data key (fresh nonce per
   chunk) before it is sent to a volume server, and the blob is stored without its
   file name or MIME type.
3. The wrapped data key is stored next to the chunk ids in the entry.
4. Reading unwraps the data key through transit (cached in memory), decrypts and
   verifies each chunk.

Consequences: volume servers only ever hold ciphertext; rotating the transit key
protects new files with the new version while old files remain readable; and
**sealing Coffer immediately makes encrypted files unreadable** (the data key cache
is wiped on seal and transit is unavailable until unsealed).

## 5. S3 gateway

`internal/s3api` translates S3 calls to filer operations.

* **Authentication** – AWS Signature Version 4 from the `Authorization` header or
  presigned query strings, with a 15‑minute clock‑skew window. `x-amz-content-sha256`
  and `Content-MD5` are verified; `aws-chunked` streaming bodies are decoded and,
  when signed, every chunk signature is checked. The implementation is tested
  against the AWS reference vectors.
* **Objects** are files; keys with `/` create folders implicitly, and empty folders
  are pruned when their last object is deleted.
* **Listing** produces keys in exact lexicographic order with prefix, delimiter,
  marker / continuation token and `encoding-type=url`.
* **Multipart uploads** stage parts under `/buckets/<b>/.uploads/<id>/` (hidden from
  listings). Completion stitches the parts' chunk lists into one entry; no data is
  copied. The ETag follows S3's `md5-of-md5s-N` convention.
* **Encryption** – bucket default encryption (`PutBucketEncryption`) maps to the
  folder setting; `x-amz-server-side-encryption: aws:kms` with an optional key id
  encrypts single objects with a named transit key.

## 6. Avoiding conflicts between the two halves

* **Separate namespaces.** Secrets live at `/v1/<mount>/…`, the filer at `/v1/fs/…`
  (the mount name `fs/` is reserved), S3 on its own port, master and volume servers
  on theirs.
* **Separate stores.** The secrets core and the filer use different kvstores, so a
  large file tree cannot slow down secret lookups and vice versa.
* **Lock discipline.** Requests hold a read lock on the seal state; sealing waits for
  in‑flight requests, then wipes keys. Long file transfers do not hold that lock;
  they fail closed if the core seals mid‑stream.
* **System mounts.** `transit/` (used for storage encryption) and `cubbyhole/`
  cannot be disabled, so storage can never lose its key engine by accident. Transit
  keys refuse deletion unless `deletion_allowed` is set explicitly.

## Scope: what Coffer does not include

Coffer implements the core of both upstream projects, not their full breadth. Not
included today:

* Standby servers / automatic failover: no Raft replication of the master or the secrets store; each
  runs as a single instance (volume data is replicated).
* Erasure coding, tiered/cloud storage, cross‑cluster replication, FUSE mount,
  WebDAV, Hadoop/HDFS compatibility.
* S3 versioning, object lock, lifecycle rules, bucket policies (JSON), CORS
  configuration storage, SSE‑C.
* Dynamic secrets engines (databases, cloud credentials, SSH), the identity system
  (entities/groups), namespaces, plugins, and auth methods beyond token, userpass
  and AppRole (no LDAP, OIDC, Kubernetes, TLS certificates).
* Leases for dynamic secrets (token TTLs and renewal are implemented).
* KMS or HSM auto‑unseal (a file‑based auto‑unseal convenience exists; see
  Operations).
* An audit write failure is logged but does not block the request (OpenBao blocks).
