package cli

import (
	"bytes"
	"strings"
	"testing"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
)

func TestTableOutputAlignsAfterANSIColor(t *testing.T) {
	var out bytes.Buffer
	handlers := []apiv1.DNSHandlerInfo{
		{ID: "short", Name: "Short", Feature: []string{"a"}, ZoneNesting: true},
		{ID: "longer-id", Name: "Longer", Feature: []string{"a", "b"}, ZoneNesting: false},
	}

	if err := PrintDNSHandlers(&out, handlers, true); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header plus two rows, got %d lines: %q", len(lines), out.String())
	}

	headerColumn := visibleIndex(lines[0], "ZONE_NESTING")
	firstColumn := visibleIndex(lines[1], "true")
	secondColumn := visibleIndex(lines[2], "false")
	if headerColumn < 0 || firstColumn < 0 || secondColumn < 0 {
		t.Fatalf("could not find expected cells in output: %q", out.String())
	}
	if headerColumn != firstColumn || headerColumn != secondColumn {
		t.Fatalf("visible column mismatch: header=%d first=%d second=%d output=%q",
			headerColumn, firstColumn, secondColumn, out.String())
	}
}

func TestPrintCertResourcesAddsCaptions(t *testing.T) {
	var out bytes.Buffer
	resources := apiv1.CertResources{
		Certificate: "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
		Key:         "-----BEGIN PRIVATE KEY-----\nZGVm\n-----END PRIVATE KEY-----\n",
	}

	if err := PrintCertResources(&out, resources, true, false); err != nil {
		t.Fatal(err)
	}

	expected := "######## Certificate (cert) ########\n" +
		resources.Certificate +
		"\n######## Private key (key) ########\n" +
		resources.Key
	if out.String() != expected {
		t.Fatalf("unexpected output:\nwant %q\ngot  %q", expected, out.String())
	}
}

func TestPrintCertResourcesColorsCaptions(t *testing.T) {
	var out bytes.Buffer
	resources := apiv1.CertResources{
		Certificate: "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
	}

	if err := PrintCertResources(&out, resources, true, true); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "\033[1;36m######## Certificate (cert) ########\033[0m") {
		t.Fatalf("caption is not highlighted: %q", out.String())
	}
}

func visibleIndex(line, needle string) int {
	plain := ansiEscapeRegexp.ReplaceAllString(line, "")
	return strings.Index(plain, needle)
}
