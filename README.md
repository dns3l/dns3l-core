# dns3l-core

[![golangci-lint](https://github.com/dns3l/dns3l-core/actions/workflows/golint.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/golint.yaml)
[![go test](https://github.com/dns3l/dns3l-core/actions/workflows/gotest.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/gotest.yaml)
[![docker-dns3ld](https://github.com/dns3l/dns3l-core/actions/workflows/docker-dns3ld.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/docker-dns3ld.yaml)


Core parts of dns3l written in Go:
- Backend daemon for [DNS3L](https://github.com/dns3l/dns3l)
- API/Libraries for DNS3L functionality

**Requires go >= 1.24**

## Implementation Status

Implemented:

- Code skeleton
- Config
- REST API returns config
- DNS handlers
- ACME handlers
- State, DB connection
- OIDC Auth
- Static token auth

Not yet implemented:

- Legacy CA handlers
- Self-service token auth support

# dns3ld (backend daemon)

## Build

Run

```
make
```

to obtain a statically linked binary.

To obtain a Docker image, run

```
make docker
```

or explicitly (same semantics)

```
docker buildx build -t dns3ld:$(awk -v FS="dns3ld=" 'NF>1{print $2}' VERSIONS)-dev -f docker/Dockerfile-dns3ld .
```

The awk command above is an example that will create the right tag name from the VERSIONS file, feel free
to choose other tag names as needed.

## Usage

```
$./dns3ld --help
DNS3LD backend daemon, version 1.5.4

Usage:
  dns3ld [flags]
  dns3ld [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dbcreate    Create database structure
  help        Help about any command

Flags:
  -b, --bootstrapcert   Whether initial bootstrapping of certs should run on this instance. Useful if multiple
                                        instances run on the same DB and you want to disable bootstrapping for the replicas. (default true)
  -c, --config string   YAML-formatted configuration for dns3ld. (default "config.yaml")
  -h, --help            help for dns3ld
  -r, --renew           Whether automatic cert renewal jobs should run. Useful if multiple instances run on the
                                        same DB and you want to disable renewal for the replicas, which is not yet thread-safe. (default true)
  -s, --socket string   L4 socket on which the service should listen. (default ":80")

Use "dns3ld [command] --help" for more information about a command.
```

Example

```
./dns3ld --config config-example.yaml --socket 127.0.0.1:8080
```

### docker-compose

Example:

```yaml
  backend:
    image: ghcr.io/dns3l/dns3ld:1.5.4
    container_name: dns3l-backend
    restart: always
    volumes:
      - /root/dns3ld.conf.yaml:/etc/dns3ld.conf.yaml:ro
    networks:
      - dns3l
    command: 
      --config=/etc/dns3ld.conf.yaml
      --socket=:8080
    dns_search: .
```

# dns3lcli (command-line API client)

`dns3lcli` is a command-line client for the dns3ld HTTP API. It can query
server, DNS and CA information, list certificates, claim and delete
certificates, and download PEM resources.

## Build

Build a local Linux binary:

```
make cli
```

The dns3lcli binary version is read from `dns3lcli=<version>` in `VERSIONS`.
The implemented API version is compiled into the CLI and shown together with
the CLI version:

```
dns3lcli version
```

The GitHub release workflow uses the same `dns3lcli=<version>` value. On
`master`, it creates a `dns3lcli-<version>` release with CLI binaries when that
release does not already exist.

Build release-style binaries for Linux, Windows and Darwin on amd64 and arm64:

```
make cli-all
```

Build a Docker image for Linux amd64 and arm64:

```
make cli-docker
```

## Configuration

By default, `dns3lcli` reads `./config.yaml`. Override the config path with
`--config` or `DNS3L_CONFIG`. Values are resolved in this order:

1. Command-line flags
2. Environment variables
3. Config file

Example `config.yaml`:

```yaml
server: https://my-server.com/api/v1
ad_user: alice@example.com
ad_password: change-me
oidc_client_id: dns3l-api
oidc_client_secret: change-me
oidc_daemon_client_id: dns3ld
timeout: 60s
timeout_claim: 10m
```

The `server` value should usually point at the API base URL. If the server is
`https://my-server.com/api/v1`, `dns3lcli` fetches OIDC tokens from
`https://my-server.com/auth/token`.

Standard Go proxy environment variables are honored for API and token
requests: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase
variants.

The most relevant flags and their config/env equivalents are:

| Flag | Config key | Environment variable |
| --- | --- | --- |
| `--config` | - | `DNS3L_CONFIG` |
| `--server` | `server` (`instance`, `dns3l_instance`) | `DNS3L_SERVER` (`DNS3L_INSTANCE`) |
| `--ad-user` | `ad_user` | `DNS3L_AD_USER` |
| `--ad-password` | `ad_password` (`ad_pass`) | `DNS3L_AD_PASSWORD` (`DNS3L_AD_PASS`) |
| `--oidc-client-id` | `oidc_client_id` (`client_id`) | `DNS3L_OIDC_CLIENT_ID` (`OIDC_CLIENT_ID`, `CLIENT_ID`) |
| `--oidc-client-secret` | `oidc_client_secret` (`client_secret`) | `DNS3L_OIDC_CLIENT_SECRET` (`OIDC_CLIENT_SECRET`, `CLIENT_SECRET`) |
| `--oidc-daemon-client-id` | `oidc_daemon_client_id` | `DNS3L_OIDC_DAEMON_CLIENT_ID` (`DAEMON_CLIENT_ID`) |
| `--token` | `token` | `DNS3L_ID_TOKEN` (`DNS3L_TOKEN`) |
| `--api-key` | `api_key` | `DNS3L_API_KEY` |
| `--timeout` | `timeout` | `DNS3L_TIMEOUT` |
| `--timeout-claim` | `timeout_claim` | `DNS3L_TIMEOUT_CLAIM` |

Run `dns3lcli --help` to see the same mappings inline with the flags.

## Authentication

For OIDC authentication, provide these values via config, environment or flags:

- `server`
- `ad_user`
- `ad_password`
- `oidc_client_id`
- `oidc_client_secret`

`dns3lcli` then requests an ID token with the OIDC password grant and sends it
as a bearer token to dns3ld.

If you already have a token, pass it directly:

```
dns3lcli --server https://my-server.com/api/v1 --token "$DNS3L_ID_TOKEN" crt list
```

Use `--no-auth` to force anonymous access. Certificate listing, certificate
metadata, and public certificate PEM data can also try anonymous access
automatically when no auth data is configured, depending on the dns3ld server
configuration. Certificate private keys and mutating operations always require
authentication.

## Common Usage

Examples without `--server` assume the server and authentication settings are
already available from the config file or environment variables.

Show server information:

```
dns3lcli --server https://my-server.com/api/v1 info
```

List DNS providers and root zones:

```
dns3lcli --server https://my-server.com/api/v1 dns
dns3lcli --server https://my-server.com/api/v1 dns rootzones
```

List CAs and show one CA:

```
dns3lcli --server https://my-server.com/api/v1 ca list
dns3lcli --server https://my-server.com/api/v1 ca get les
```

List certificates:

```
dns3lcli --server https://my-server.com/api/v1 crt list
dns3lcli --server https://my-server.com/api/v1 crt list --ca les
```

Show certificate metadata:

```
dns3lcli --server https://my-server.com/api/v1 crt get --ca les www.example.com
dns3lcli --server https://my-server.com/api/v1 crt get www.example.com
```

Without `--ca`, `crt get` queries across CAs and returns the single matching
certificate. It fails if no certificate exists, or if multiple entries are
returned and `--ca` is needed to disambiguate. With `--json`, `crt get` prints
one JSON object rather than a one-element list.

Claim a certificate:

```
dns3lcli crt claim les \
  --name www.example.com \
  --san alt.example.com \
  --autodns-ipv4 192.0.2.10 \
  --ttl 30
```

Claiming a certificate can take several minutes. `dns3lcli` prints progress to
stderr while the request is running. Claim requests use `--timeout-claim`
(`timeout_claim`, `DNS3L_TIMEOUT_CLAIM`), which defaults to `10m`. Other
requests use `--timeout`, which defaults to `60s`.

Delete a certificate:

```
dns3lcli crt delete --ca les www.example.com
dns3lcli crt delete www.example.com
```

## PEM Downloads

Download one PEM resource to stdout:

```
dns3lcli crt pem les www.example.com crt
dns3lcli crt pem les www.example.com fullchain
```

Download one PEM resource to a file:

```
dns3lcli crt pem les www.example.com fullchain --output www.example.com-fullchain.pem
```

Download all PEM resources to stdout:

```
dns3lcli crt pem les www.example.com
```

When all PEM resources are written to stdout, each resource is preceded by a
visible caption such as `######## Certificate (cert) ########`. Captions are
highlighted when terminal colors are supported. Single-resource PEM downloads
remain raw PEM for piping and file redirection.

Download all PEM resources to a directory:

```
dns3lcli crt pem les www.example.com --output-dir ./www.example.com-pem
```

PEM output is validated by default. Disable the check with `--no-pem-check`
when you need to inspect invalid or partial server output.

The single-resource PEM command supports `crt`, `key`, `chain`, `root`,
`rootchain` and `fullchain`. Private key downloads require authentication.

## Output and Troubleshooting

By default, `dns3lcli` prints human-readable tables or key/value output. Use
`--json` to print JSON output. Most commands print the raw API response;
`crt get` unwraps the all-CA API response and prints one certificate object.

```
dns3lcli --json crt list --ca les
```

Debug and trace logs are written to stderr:

```
dns3lcli --debug crt list
dns3lcli --trace crt get --ca les www.example.com
```

Use command-specific help for the exact command syntax:

```
dns3lcli --help
dns3lcli crt --help
dns3lcli crt pem --help
```

## Test

### Unit tests

```
export DNS3L_TEST_CONFIG=/my/secret/folder/dns3l-config4test.yaml
go test ./...
```

### Component tests

Component tests will test with real DB endpoints without
using the Golang unit test framework.

```
make comptest
```

You can also use the Docker version of the component tests:

```
make comptest-docker
```
