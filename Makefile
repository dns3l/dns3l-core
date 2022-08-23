.PHONY : test cli service


GOARCH = amd64
# GO_LDFLAGS := "-X 'github.com/dta4/dns3l-go/context.Version=1.0.0' -extldflags '-static' -w -s"
GO_LDFLAGS := "-X 'github.com/markusBayerbach/dns3l-go/context.Version=1.0.0' -extldflags '-static' -w -s"
GOENV := GOARCH=$(GOARCH) GOOS=linux
GODIRS := ./acme/... ./ca/... ./commands/... ./cmd/... ./context/...  ./dns/... ./service/... ./util/... ./cli/...

service:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3ld ./cmd/dns3ld/.

cli:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3lcli ./cmd/dns3lcli/.	

test:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out

comptest:
	$(GOENV) go run ./test/.
