# dns3l-core

[![golangci-lint](https://github.com/dns3l/dns3l-core/actions/workflows/golint.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/golint.yaml)
[![go test](https://github.com/dns3l/dns3l-core/actions/workflows/gotest.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/gotest.yaml)
[![docker-dns3ld](https://github.com/dns3l/dns3l-core/actions/workflows/docker-dns3ld.yaml/badge.svg)](https://github.com/dns3l/dns3l-core/actions/workflows/docker-dns3ld.yaml)


Core parts of dns3l written in Go:
- Backend daemon for [DNS3L](https://github.com/dta4/dns3l)
- API/Libraries for DNS3L functionality

## Implementation Status

Implemented:

- Code skeleton
- Config
- REST API returns config
- DNS handlers
- ACME handlers
- State, DB connection
- Auth

Not yet implemented:

- Legacy CA handlers

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
docker build -t dns3ld:$(awk -v FS="dns3ld=" 'NF>1{print $2}' VERSIONS)-dev -f docker/Dockerfile-dns3ld .
```

The awk command above is an example that will create the right tag name from the VERSIONS file, feel free
to choose other tag names as needed.

## Usage

```
$./dns3ld --help
DNS3LD backend daemon, version 1.0.0

Usage:
  dns3ld [flags]
  dns3ld [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dbcreate    Create database structure
  help        Help about any command

Flags:
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
    image: ghcr.io/dns3l/dns3ld:1.0.1
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

## Test

### Unit tests

```
export DNS3L_TEST_CONFIG=/my/secret/folder/dns3l-config4test.yaml
go test ./...
```

### Component tests

Component tests will test with real (maybe non-production but staging) endpoints without
using the Golang unit test framework. Therefore, credentials must be given in a config 
derived from the `config-example.yaml` format.

```
export DNS3L_TEST_CONFIG=/my/secret/folder/dns3l-config4test.yaml
make comptest
```
