# dns3l-go

Go parts of dns3l:
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

# Build

Run

```
make
```

to obtain a statically linked binary.

To obtain a Docker image, run

```
docker build -t <tag-name> -f docker/Dockerfile-dns3ld .
```

# Usage

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
  -s, --socket string   L4 socket on which the service should listen. (default ":80")

Use "dns3ld [command] --help" for more information about a command.
```

Example

```
./dns3ld --config config-example.yaml --socket 127.0.0.1:8080
```

# Test

dns3ld will test with real (maybe non-production but staging) endpoints.
Therefore, credentials must be given in the `config-example.yaml` format.

```
export DNS3L_TEST_CONFIG=/my/secret/folder/dns3l-config4test.yaml
go test ./...
```
