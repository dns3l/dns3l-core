.PHONY : test cli cli-all cli-docker service


DOCKER = /usr/bin/docker
GOARCH ?= amd64
DNS3LD_VERSION = $(shell awk -v FS="dns3ld=" 'NF>1{print $$2}' VERSIONS)
DNS3LCLI_VERSION = $(shell awk -v FS="dns3lcli=" 'NF>1{print $$2}' VERSIONS)
GO_LDFLAGS := "\
	-X 'github.com/dns3l/dns3l-core/context.ServiceVersion=$(DNS3LD_VERSION)' \
	-extldflags '-static' -w -s"
GO_CLI_LDFLAGS := "\
	-X 'github.com/dns3l/dns3l-core/context.ServiceVersion=$(DNS3LCLI_VERSION)' \
	-extldflags '-static' -w -s"
GOENV := GOARCH=$(GOARCH) GOOS=linux
GOCLIENV := CGO_ENABLED=0 GOARCH=$(GOARCH) GOOS=linux
GODIRS := ./ca/... ./cmd/... ./context/...  ./dns/... ./service/... ./util/... ./renew/... ./cli/...
DOCKER_COMPTEST := $(DOCKER) run -v $(shell pwd):/workdir -t golang:1.24-alpine /workdir/docker/run-in-docker golang-alpine

all: service

service:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3ld ./cmd/dns3ld/.

cli:
	$(GOCLIENV) go build -v -ldflags $(GO_CLI_LDFLAGS) -o dns3lcli ./cmd/dns3lcli/.

cli-all:
	mkdir -p dist
	set -e; \
	for goos in linux windows darwin; do \
		for goarch in amd64 arm64; do \
			ext=""; \
			if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
			out="dist/dns3lcli_$(DNS3LCLI_VERSION)_$${goos}_$${goarch}$${ext}"; \
			CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build -v -ldflags $(GO_CLI_LDFLAGS) -o "$$out" ./cmd/dns3lcli/.; \
			gzip -f "$$out"; \
		done; \
	done

docker: cli-docker service-docker

cli-docker:
	$(DOCKER) buildx build --network host --platform linux/amd64,linux/arm64 --build-arg https_proxy=${https_proxy} -t dns3lcli:$(DNS3LCLI_VERSION)-dev -f docker/Dockerfile-dns3lcli .

docker-simple: service-docker-simple

service-docker:
	$(DOCKER) buildx build --network host --platform linux/amd64,linux/arm64 --build-arg https_proxy=${https_proxy} -t dns3ld:$(DNS3LD_VERSION)-dev -f docker/Dockerfile-dns3ld .

service-docker-simple:
	$(DOCKER) buildx build --network host --platform linux/amd64,linux/arm64 --build-arg https_proxy=${https_proxy} -t dns3ld-simple:$(DNS3LD_VERSION)-dev -f docker/Dockerfile-dns3ld-simple .

test: unittest comptest

unittest:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out

comptest:
	$(GOENV) go run ./test/main.go dbfull

comptest-acmestep:
	$(GOENV) go run ./test/main.go acmestep

comptest-docker:
	$(DOCKER_COMPTEST) dbfull

comptest-acmestep-docker:
	$(DOCKER_COMPTEST) acmestep

clean: comptest-clean

comptest-clean:
	rm -r testdata
