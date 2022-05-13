.PHONY : test

GOARCH = amd64
GO_LDFLAGS := "-X 'github.com/dta4/dns3l-go/context.Version=1.0.0' -extldflags '-static' -w -s"
GOENV := GOARCH=$(GOARCH) GOOS=linux CGO_ENABLED=0 
GODIRS := ./acme/... ./cmd/... ./dns/... ./service/... ./util/... ./context/...

build:
	$(GOENV) go build -v -ldflags $(GO_LDFLAGS) -o dns3ld .

test:
	$(GOENV) go test $(GODIRS) -coverprofile coverage.out
	$(GOENV) go tool cover -func=coverage.out
