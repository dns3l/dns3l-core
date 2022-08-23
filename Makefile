.PHONY : test cli service


GOARCH = amd64
DNS3LD_VERSION = $(shell awk -v FS="dns3ld=" 'NF>1{print $$2}' VERSIONS)
DNS3LCLI_VERSION = $(shell awk -v FS="dns3lcli=" 'NF>1{print $$2}' VERSIONS)
GO_LDFLAGS := "\
	-X 'github.com/dns3l/dns3l-core/context.ServiceVersion=$(DNS3LD_VERSION)' \
	-X 'github.com/dns3l/dns3l-core/context.CLIVersion=$(DNS3LCLI_VERSION)' \
	-extldflags '-static' -w -s"
GOENV := GOARCH=$(GOARCH) GOOS=linux
GODIRS := ./acme/... ./ca/... ./commands/... ./cmd/... ./context/...  ./dns/... ./service/... ./util/... ./cli/... ./renew/...

all: service cli

service:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3ld ./cmd/dns3ld/.

cli:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3lcli ./cmd/dns3lcli/.	

test:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out

comptest:
	$(GOENV) go run ./test/.
