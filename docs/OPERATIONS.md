# Operations

## Ports

| Port | Process | Purpose | Expose to |
|---|---|---|---|
| 8200 | `coffer server` | HTTP API, filer API, web console, share links | users and apps |
| 8333 | `coffer server` | S3 gateway | S3 clients |
| 9333 | master | file id assignment, topology | cluster only |
| 8080 | volume server | blob reads/writes, replication | cluster only |

Keep 9333 and 8080 on a private network. Even so, set a cluster secret: without it,
anyone who can reach those ports can read and delete blobs.

## Single node (all in one)

```bash
coffer server -dir=/var/lib/coffer -ip=10.0.0.5 \
  -tls.cert=/etc/coffer/tls.crt -tls.key=/etc/coffer/tls.key \
  -public-url=https://coffer.example.com:8200
```

This runs a master, one volume server, the secrets core, filer, S3 and the console in
one process. A cluster secret is generated automatically in `<dir>/cluster.secret`.
Then initialize and unseal (console or `coffer operator init` / `unseal`).

Data layout under `-dir`:

```
vault/          encrypted secrets store (WAL + snapshot)
filer/          file and folder metadata
master/         master state (max volume id, id sequence)
volume/         *.dat / *.idx volume files
cluster.secret  shared secret for internal calls
```

### systemd

```ini
[Unit]
Description=Coffer
After=network-online.target

[Service]
User=coffer
ExecStart=/usr/local/bin/coffer server -dir=/var/lib/coffer -ip=10.0.0.5
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/coffer

[Install]
WantedBy=multi-user.target
```

After every restart Coffer is sealed until key holders unseal it.

## Multi‑node cluster

Run one master, any number of volume servers, and one gateway. All of them must
share the same secret.

```bash
export COFFER_CLUSTER_SECRET=$(openssl rand -hex 24)   # same value on every node

# master (10.0.0.10)
coffer master -dir=/var/lib/coffer-master -defaultReplication=010

# volume servers – label racks/data centers so replication can spread copies
coffer volume -dir=/data/v -ip=10.0.0.21 -master=10.0.0.10:9333 -dataCenter=dc1 -rack=r1 -max=64
coffer volume -dir=/data/v -ip=10.0.0.22 -master=10.0.0.10:9333 -dataCenter=dc1 -rack=r2 -max=64
coffer volume -dir=/data/v -ip=10.0.0.23 -master=10.0.0.10:9333 -dataCenter=dc1 -rack=r2 -max=64

# gateway (secrets, filer, S3, UI) without its own volume server
coffer server -dir=/var/lib/coffer -master=10.0.0.10:9333 -volume.disable -replication=010
```

`docker-compose.yml` in the repository sets up exactly this shape.

* **Adding capacity** – start another volume server; it joins on its first
  heartbeat and new volumes are placed on it.
* **Losing a server** – after 12 s it is marked offline. Data with replication
  ≥ 1 copy elsewhere stays readable; affected volumes show as *degraded* and stop
  taking writes; new writes go to other volumes.
* **Volume size** – `-volumeSizeLimitMB` on the master (default 1024). Full volumes
  become read‑only and new ones are created automatically.

## Server flags

`coffer server`:

| Flag | Default | Meaning |
|---|---|---|
| `-dir` | `./coffer-data` | data directory |
| `-ip` | `127.0.0.1` | address other components use to reach this node |
| `-bind` | `0.0.0.0` | listen address |
| `-port` | 8200 | API + console |
| `-s3.port` | 8333 | S3 gateway |
| `-master.port` / `-volume.port` | 9333 / 8080 | embedded master / volume server |
| `-master` | (embedded) | external master `host:port` |
| `-volume.disable` | false | no embedded volume server |
| `-volume.max` | 16 | volume slots on the embedded volume server |
| `-volume.sizeLimitMB` | 1024 | volume size limit (embedded master) |
| `-replication` | `000` | default replication for new files |
| `-dataCenter`, `-rack` | `dc1`, `rack1` | location of the embedded volume server |
| `-chunkSizeMB` | 4 | file chunk size |
| `-cluster.secret` | auto | shared secret (or `COFFER_CLUSTER_SECRET`) |
| `-tls.cert`, `-tls.key` | | serve API and S3 over HTTPS |
| `-s3.domain` | | enables virtual‑hosted buckets (`bucket.s3.example.com`) |
| `-s3.region` | `us-east-1` | region reported to S3 clients |
| `-public-url` | `http(s)://ip:port` | base URL used in share links |
| `-unseal-key-file` | | auto‑unseal at start (see below) |
| `-dev`, `-dev.root-token` | | development mode |

`coffer master`: `-port -bind -dir -volumeSizeLimitMB -defaultReplication -cluster.secret`

`coffer volume`: `-port -bind -ip -publicUrl -dir -master -max -dataCenter -rack -cluster.secret`

Set `COFFER_LOG_REQUESTS=1` to log every API request.

## TLS

Pass `-tls.cert` and `-tls.key` to serve the API, console and S3 over HTTPS
(TLS 1.2+). Clients then use `COFFER_ADDR=https://…`. Internal master/volume
traffic is authenticated by the cluster secret; run it on a private network or
behind a mesh/VPN if you need it encrypted in transit as well. Data in encrypted
folders is already ciphertext on that link.

## Key ceremonies

| Task | Console | CLI |
|---|---|---|
| Rotate the barrier key | System → Rotate key | `coffer operator rotate` |
| Replace unseal keys | System → Rekey | `coffer operator rekey -keys=k1,k2,k3 -key-shares=5 -key-threshold=3` |
| New root token | — | `coffer operator generate-root -keys=k1,k2,k3` |
| Revoke the initial root token | Access → Tokens | `coffer token revoke <token>` |

Recommended after setup: create admin users with an operator policy, then revoke
the initial root token. Generate a temporary one when you need it.

### Auto‑unseal file

`-unseal-key-file=/path` reads unseal keys (one per line) at startup. This trades
the protection of the seal for convenience: anyone with that file and the data
directory can decrypt everything. Only use it when the file lives on separate,
protected storage (e.g. a secrets mount provided by your orchestrator), never next
to the data.

## Backups and disaster recovery

### Snapshots (recommended)

One command backs up everything the gateway owns – secrets, policies, tokens,
auth config, audit settings, the file index and master state – into a single
checksummed file:

```bash
coffer operator snapshot save coffer-2026-11-25.snap      # needs a root/sudo token
```

or **System → Backup and disaster recovery → Download snapshot** in the console.
Secrets stay barrier‑encrypted inside the snapshot, so it is useless without a
quorum of unseal keys. Store keys and snapshots in different places. Schedule it
with cron / Task Scheduler (e.g. every 6 hours).

File **contents** are not in the snapshot: they live on volume servers and are
protected by replication (`001`, `010`, …). Back up the `.dat/.idx` volume files
as well if you run without replication.

### Recovery runbook

| Failure | Recovery |
|---|---|
| Gateway disk lost / `vault` or `filer` corrupted | Stop the server, `coffer operator snapshot restore -dir=<data-dir> <file>`, start, unseal. Old folders are kept as `*.bak-<time>`. |
| Moving to a new machine | Copy the snapshot, restore into an empty data dir there, point it at the same master/volume servers (or copy the volume folders), start, unseal. |
| One volume server lost | Nothing to do if replication ≥ 2 copies; data is served from the other replica. Replace the server; new writes go to healthy volumes. |
| Root token lost | `coffer operator generate-root -keys=…` |
| Fewer unseal keys than the threshold survive | Not recoverable – by design. Rekey while you still have a quorum. |

Restore brings data back to the moment of the snapshot: secrets written and files
uploaded after it are not in it (uploaded chunks of newer files become unused and
are reclaimed by vacuum).

## Monitoring

* `GET /v1/sys/health` – 200 when unsealed, 503 sealed, 501 not initialized. Use it
  as a load balancer health check.
* `GET /v1/sys/seal-status` – unauthenticated seal details.
* `GET /v1/sys/storage/status` (token with access) – topology, volumes, totals,
  filer statistics.
* Master `GET /healthz`, volume `GET /healthz`.
* Audit log destinations (`file` type; `stdout` works for container log collectors).

## Capacity & tuning

* Each volume server keeps an in‑memory map of its needles (≈40 bytes per file).
* The filer keeps metadata in memory with a write‑ahead log; plan roughly 1 KB of
  RAM per file or folder.
* Larger `-chunkSizeMB` reduces metadata for very large files; smaller chunks give
  finer range reads.
* Run **Reclaim space** (vacuum) after mass deletions to get disk back immediately.

## Upgrading

Stop the processes, replace the binary, start them again and unseal. On‑disk
formats carry version bytes (barrier ciphertext, needle superblock) so future
releases can migrate data in place.
