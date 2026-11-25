# API reference

All API calls go to `http(s)://<host>:8200/v1/…`. Authenticate with one of:

```
X-Coffer-Token: cof.xxxxx      (X-Vault-Token is also accepted)
Authorization: Bearer cof.xxxxx
```

Responses use the familiar envelope:

```json
{ "request_id": "…", "data": { … }, "auth": null, "wrap_info": null, "warnings": null,
  "lease_id": "", "lease_duration": 0, "renewable": false }
```

Errors return `{"errors": ["message"]}` with a meaningful status: 400 bad input,
403 permission denied, 404 not found, 409 conflict, 429 locked out, 503 sealed.

Methods: `GET` read, `LIST` (or `GET ?list=true`) list, `POST`/`PUT` create or
update, `PATCH` patch, `DELETE` delete. Add `X-Coffer-Wrap-TTL: 10m` to any request
to receive a single‑use wrapping token instead of the response.

## sys – seal and system

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/sys/init` | none | `{initialized}` |
| PUT | `/sys/init` | none | `{secret_shares, secret_threshold}` → keys, keys_base64, root_token |
| GET | `/sys/seal-status` | none | `{sealed, t, n, progress, initialized, version}` |
| PUT | `/sys/unseal` | none | `{key}` or `{reset:true}` |
| PUT | `/sys/seal` | sudo | seal now |
| GET | `/sys/health` | none | 200 / 503 sealed / 501 uninitialized |
| PUT | `/sys/generate-root` | none (needs keys) | `{keys:[…]}` → new root token |
| PUT | `/sys/rekey` | sudo | `{keys:[…], secret_shares, secret_threshold}` → new keys |
| GET | `/sys/key-status` | token | active barrier term |
| PUT | `/sys/rotate` | sudo | add a barrier key term |
| GET | `/sys/mounts` | token | secrets engines |
| POST/DELETE | `/sys/mounts/<path>` | token | enable `{type, description, options}` / disable |
| GET | `/sys/auth` | token | auth methods |
| POST/DELETE | `/sys/auth/<path>` | token | enable `{type}` / disable |
| LIST | `/sys/policies/acl` | token | policy names |
| GET/PUT/DELETE | `/sys/policies/acl/<name>` | token | `{policy: "<hcl or json>"}` |
| POST | `/sys/capabilities-self` | token | `{path}` or `{paths}` → capabilities |
| POST | `/sys/capabilities` | token | `{token, paths}` |
| GET | `/sys/audit` | sudo | audit devices |
| PUT/DELETE | `/sys/audit/<name>` | sudo | `{type:"file", options:{file_path}}` |
| GET | `/sys/audit-events?limit=&filter=` | sudo | recent events |
| POST | `/sys/wrapping/wrap` | token | wrap the request body |
| POST | `/sys/wrapping/unwrap` | wrapping token | `{token}` or token header |
| POST | `/sys/wrapping/lookup` | wrapping token | creation info |
| GET | `/sys/internal/ui/mounts` | token | mounts visible to this token |
| GET | `/sys/storage/status` | token | topology, volumes, filer stats, S3 port |
| GET | `/sys/storage/snapshot` | sudo | download a snapshot (restore is offline via the CLI) |
| POST | `/sys/storage/grow` | token | `{count, collection, replication, ttl}` |
| POST | `/sys/storage/vacuum` | token | `{garbage_threshold}` |
| GET/POST | `/sys/s3/keys` | token | list keys / create `{policies, description, access_key?}` → secret shown once |
| GET/POST/DELETE | `/sys/s3/keys/<access_key>` | token | read / update description / delete |
| GET | `/sys/shares` | token | active share links (own, or all for root) |
| DELETE | `/sys/shares/<id>` | token | revoke a link |

## auth

| Method | Path | Description |
|---|---|---|
| POST | `/auth/token/create` | `{policies, ttl, explicit_max_ttl, num_uses, renewable, no_parent, display_name, meta, no_default_policy}` |
| POST | `/auth/token/create-orphan` | same, as an orphan (sudo) |
| GET | `/auth/token/lookup-self` | |
| POST | `/auth/token/lookup` / `lookup-accessor` | `{token}` / `{accessor}` |
| POST | `/auth/token/renew-self` / `renew` | `{increment}` |
| POST | `/auth/token/revoke-self` / `revoke` / `revoke-orphan` / `revoke-accessor` | |
| LIST | `/auth/token/accessors` | sudo |
| POST | `/auth/userpass/login/<user>` | `{password}` → `auth.client_token` |
| LIST/GET/POST/DELETE | `/auth/userpass/users/<user>` | `{password, policies, token_ttl, token_max_ttl, token_bound_cidrs}` |
| POST | `/auth/userpass/users/<user>/password` / `policies` | |
| POST | `/auth/approle/login` | `{role_id, secret_id}` |
| LIST/GET/POST/DELETE | `/auth/approle/role/<name>` | `{token_policies, token_ttl, token_max_ttl, secret_id_ttl, secret_id_num_uses, bind_secret_id, secret_id_bound_cidrs}` |
| GET/POST | `/auth/approle/role/<name>/role-id` | read / set |
| POST/LIST | `/auth/approle/role/<name>/secret-id` | generate / list accessors |
| POST | `/auth/approle/role/<name>/secret-id/destroy` | `{secret_id}` |

## Secrets engines

### KV v2 (`secret/` by default)

| Method | Path | Description |
|---|---|---|
| GET | `/secret/data/<path>?version=N` | read (404 with metadata if deleted) |
| POST/PUT | `/secret/data/<path>` | `{data:{…}, options:{cas:N}}` |
| PATCH | `/secret/data/<path>` | merge into the current version |
| DELETE | `/secret/data/<path>` | soft‑delete latest version |
| POST | `/secret/delete/<path>` · `undelete/<path>` · `destroy/<path>` | `{versions:[…]}` |
| LIST | `/secret/metadata/<path>` | list keys and folders |
| GET/POST/DELETE | `/secret/metadata/<path>` | history; `{max_versions, cas_required, custom_metadata}`; delete all |
| GET/POST | `/secret/config` | `{max_versions, cas_required}` |

KV v1 (`type: kv`): `GET/POST/DELETE/LIST /<mount>/<path>`.

### Transit (`transit/`)

| Path | Description |
|---|---|
| `keys/<name>` | POST create `{type: aes256-gcm96 · aes128-gcm96 · ed25519 · ecdsa-p256 · hmac, derived, exportable, auto_rotate_period}`, GET, DELETE (needs `deletion_allowed`) |
| `keys/<name>/rotate` · `config` · `trim` | rotate; `{min_decryption_version, min_encryption_version, deletion_allowed, exportable, auto_rotate_period}`; `{min_available_version}` |
| `encrypt/<name>` | `{plaintext(b64), context(b64)?, key_version?}` or `{batch_input:[…]}` |
| `decrypt/<name>` · `rewrap/<name>` | `{ciphertext, context?}` |
| `datakey/plaintext/<name>` · `datakey/wrapped/<name>` | `{bits: 128·256·512}` |
| `hmac/<name>[/<algo>]` · `verify/<name>` | `{input}`; `{input, hmac}` or `{input, signature}` |
| `sign/<name>` | `{input}` (Ed25519/ECDSA keys) |
| `export/<encryption-key·signing-key·hmac-key>/<name>` | exportable keys only |
| `random[/<bytes>]` · `hash[/<algo>]` | utilities |

### PKI (`pki/`)

| Path | Description |
|---|---|
| `root/generate/internal` · `exported` | `{common_name, ttl, key_type: ec·rsa, key_bits, organization}` |
| `root` (DELETE) | remove the CA |
| `ca` · `ca/pem` · `crl` · `crl/pem` | unauthenticated downloads |
| `cert/ca` · `certs` (LIST) · `cert/<serial>` | |
| `roles/<name>` | `{allowed_domains, allow_subdomains, allow_bare_domains, allow_any_name, allow_localhost, allow_ip_sans, ttl, max_ttl, key_type, key_bits, server_flag, client_flag, organization}` |
| `issue/<role>` | `{common_name, alt_names, ip_sans, ttl}` → certificate, private_key, issuing_ca |
| `sign/<role>` | `{csr, common_name?, ttl}` |
| `revoke` · `crl/rotate` | `{serial_number}` |

### TOTP · Cubbyhole

* TOTP: `keys/<name>` `{generate:true, issuer, account_name}` or `{key|url}`; `GET code/<name>`; `POST code/<name> {code}` → `{valid}`.
* Cubbyhole: `GET/POST/DELETE/LIST /cubbyhole/<path>` – private to the calling token.

## Files – `/v1/fs/<path>`

Permissions are checked against `fs/<path>`.

| Method | Query | Description |
|---|---|---|
| GET (folder) | `limit, after, prefix, hidden` | `{entries, more, entry, effective_config}` (needs `list`) |
| GET (file) | `download=true` | file content with Range/ETag support (needs `read`) |
| GET (file) | `meta=true` | entry with chunks |
| PUT | `ttl` | upload the request body as the file (`create`/`update`) |
| POST | `op=upload` | multipart/form-data, one or more files into this folder |
| POST | `op=mkdir` | create folder (and parents) |
| POST | `op=rename&to=/new/path[&overwrite=true]` | move (`delete` on source, `create` on target) |
| POST | `op=copy&to=/new/path` | copy data (re‑encrypted for the target) |
| POST | `op=config` | `{encryption_key, replication, ttl}` folder settings (`update`) |
| POST | `op=share` | `{ttl, max_downloads}` → share link (`read`) |
| POST | `op=public` | `{public: bool}` on `/buckets/<name>` |
| DELETE | `recursive=true` | delete file or folder |

Share links: `GET /share/<id>` (no token) streams the file until it expires or the
download limit is reached.

## S3 – port 8333

Path‑style (`http://host:8333/bucket/key`) or virtual‑hosted with `-s3.domain`.
Signature V4 (header or presigned). Supported operations:

* Service: ListBuckets
* Bucket: CreateBucket, DeleteBucket, HeadBucket, ListObjects, ListObjectsV2,
  GetBucketLocation, GetBucketVersioning (unversioned), GetBucketAcl,
  Put/Get/DeleteBucketEncryption, DeleteObjects, ListMultipartUploads
* Object: PutObject, GetObject (Range, conditional, `response-*` overrides),
  HeadObject, DeleteObject, CopyObject (COPY/REPLACE metadata),
  Get/Put/DeleteObjectTagging, GetObjectAcl
* Multipart: Create, UploadPart, UploadPartCopy, Complete, Abort, ListParts
* Headers: `x-amz-meta-*`, `Content-*`, `Cache-Control`, `x-amz-tagging`,
  `x-amz-server-side-encryption[-aws-kms-key-id]`, `Content-MD5`,
  `x-amz-content-sha256` (incl. streaming), `If-Match` / `If-None-Match` on writes

## Master – port 9333 (internal)

All endpoints need a cluster token when a secret is set.

| Path | Description |
|---|---|
| `/dir/assign?collection=&replication=&ttl=&count=` | `{fid, url, publicUrl, auth}` |
| `/dir/lookup?volumeId=` | replica locations |
| `/dir/heartbeat` (POST) | volume server state |
| `/dir/status` | full topology |
| `/vol/grow?count=&collection=&replication=&ttl=` | create volumes |
| `/vol/vacuum?garbageThreshold=` | compact volumes |
| `/col/delete?collection=` | drop a collection |
| `/healthz` | liveness (no auth) |

## Volume server – port 8080 (internal)

| Method | Path | Description |
|---|---|---|
| GET/HEAD | `/<fid>` | read blob (Range supported) |
| PUT/POST | `/<fid>?ttl=` | write blob (raw body or multipart), replicated |
| DELETE | `/<fid>` | delete, replicated |
| GET | `/status` | volumes |
| POST | `/admin/assign_volume`, `/admin/vacuum`, `/admin/delete_volume`, `/admin/readonly` | master‑driven admin |
| GET | `/healthz` | liveness |
