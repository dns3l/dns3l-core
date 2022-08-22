.PHONY : test

GOARCH = amd64
DNS3LD_VERSION = 1.0.0
GO_LDFLAGS := "-X 'github.com/dta4/dns3l-go/context.Version=$(DNS3LD_VERSION)' -extldflags '-static' -w -s"
GOENV := GOARCH=$(GOARCH) GOOS=linux
GODIRS := ./acme/... ./cmd/... ./dns/... ./service/... ./util/... ./context/...

build:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3ld ./cmd/dns3ld/.

test:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out

comptest:
	$(GOENV) go run ./test/.
