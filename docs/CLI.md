# CLI reference

The `coffer` binary is both the server and the client. Client commands talk to
`COFFER_ADDR` (default `http://127.0.0.1:8200`) using `COFFER_TOKEN` or the token
saved by `coffer login` in `~/.coffer-token`.

## Servers

```
coffer server  [flags]   all-in-one node (see OPERATIONS.md for flags)
coffer master  [flags]   standalone master
coffer volume  [flags]   standalone volume server
coffer version
```

## Operator

```
coffer status                                   seal status
coffer operator init [-key-shares=5] [-key-threshold=3]
coffer operator unseal [key]                    prompts if no key given
coffer operator seal
coffer operator rotate                          new barrier key term
coffer operator rekey -keys=k1,k2,k3 [-key-shares=N] [-key-threshold=T]
coffer operator generate-root -keys=k1,k2,k3
coffer operator snapshot save <file>                       backup (online)
coffer operator snapshot restore -dir=./coffer-data <file>  restore (server stopped)
```

## Authentication

```
coffer login [token]                                       token login
coffer login -method=userpass username=alice [password=…]  prompts for password
coffer login -method=approle role_id=… secret_id=…
coffer login -method=userpass -path=corp username=alice    custom mount path
```

## Secrets

```
coffer kv put    secret/app/db user=svc pass=@pass.txt     @file reads a file, - reads stdin
coffer kv put    -cas=3 secret/app/db pass=new             check-and-set
coffer kv patch  secret/app/db pass=rotated
coffer kv get    [-version=N] secret/app/db
coffer kv list   secret/app
coffer kv delete [-versions=1,2] secret/app/db             soft delete
coffer kv undelete -versions=2 secret/app/db
coffer kv destroy  -versions=1 secret/app/db               permanent
coffer kv metadata secret/app/db

coffer read   <path>                 generic GET, e.g. coffer read pki/cert/ca
coffer write  <path> k=v …           generic PUT, e.g. coffer write transit/keys/app type=ed25519
coffer list   <path>
coffer delete <path>
```

## Tokens and policies

```
coffer token create [-policy=a,b] [-ttl=1h] [-use-limit=N] [-orphan]
coffer token lookup [token]
coffer token renew [-ttl=1h]
coffer token revoke [token]           revokes your own token if omitted

coffer policy list
coffer policy read  <name>
coffer policy write <name> <file|->
coffer policy delete <name>
```

## Engines and auth methods

```
coffer secrets list
coffer secrets enable [-path=p] [-description=…] <kv|kv-v2|transit|pki|totp>
coffer secrets disable <path>
coffer auth list
coffer auth enable [-path=p] <userpass|approle>
coffer auth disable <path>
```

## Files

```
coffer fs ls    [/path]
coffer fs put   ./local.file /remote/dir/        trailing slash keeps the file name
coffer fs get   /remote/file [local]
coffer fs cat   /remote/file
coffer fs stat  /remote/file                     metadata and chunks
coffer fs mkdir /remote/dir
coffer fs mv    /from /to
coffer fs cp    /from /to
coffer fs rm    [-r] /path
coffer fs share [-ttl=24h] [-max-downloads=N] /remote/file
coffer fs encrypt -key=<transit-key> [-replication=010] [-ttl=30d] /folder
```

## S3 keys and cluster

```
coffer s3 keys-create -policy=bucket-rw [-description=…]
coffer s3 keys-list
coffer s3 keys-delete <access-key>

coffer cluster status
coffer cluster grow   [-count=2] [-collection=c] [-replication=001]
coffer cluster vacuum [-garbageThreshold=0.3]
```
