.PHONY : test cli service


DOCKER = /usr/bin/docker
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

docker: service-docker

docker-simple: service-docker-simple

service-docker:
	$(DOCKER) build -t dns3ld:$(DNS3LD_VERSION)-dev -f docker/Dockerfile-dns3ld .

service-docker-simple:
	$(DOCKER) build -t dns3ld-simple:$(DNS3LD_VERSION)-dev -f docker/Dockerfile-dns3ld-simple .

test: unittest comptest

unittest:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out

comptest:
	$(GOENV) go run ./test/main.go dbfull

comptest-docker:
	$(DOCKER) run -v $(shell pwd):/workdir -t golang:1.19-alpine /workdir/docker/run-in-docker golang-alpine

clean: comptest-clean

comptest-clean:
	rm -r testdata
