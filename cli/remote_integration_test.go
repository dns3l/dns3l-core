package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRemoteInstanceAllCommands(t *testing.T) {
	if os.Getenv("DNS3L_REMOTE_TEST") != "1" {
		t.Skip("set DNS3L_REMOTE_TEST=1 to run against a remote DNS3L instance")
	}
	caID := strings.TrimSpace(os.Getenv("DNS3L_REMOTE_TEST_CA"))
	domain := strings.Trim(strings.TrimSpace(os.Getenv("DNS3L_REMOTE_TEST_DOMAIN")), ".")
	if caID == "" || domain == "" {
		t.Skip("DNS3L_REMOTE_TEST_CA and DNS3L_REMOTE_TEST_DOMAIN are required")
	}

	prefix := fmt.Sprintf("dns3lcli-%d", time.Now().UnixNano())
	certName := prefix + "." + domain
	deleteCertName := prefix + "-delete." + domain
	autodnsIPv4 := strings.TrimSpace(os.Getenv("DNS3L_REMOTE_TEST_AUTODNS_IPV4"))

	results := make([]string, 0, 20)
	run := func(name string, args ...string) string {
		out, errOut, err := executeRemoteCommand(args...)
		if err != nil {
			results = append(results, fmt.Sprintf("FAIL %s: %v stderr=%q", name, err, errOut))
			t.Fatalf("%s failed: %v\nstderr: %s\nstdout: %s", name, err, errOut, out)
		}
		results = append(results, "PASS "+name)
		return out
	}
	defer func() {
		if t.Failed() {
			_, _, _ = executeRemoteCommand("crt", "delete", "--ca", caID, certName)
			_, _, _ = executeRemoteCommand("crt", "delete", "--ca", caID, deleteCertName)
		}
		t.Logf("Remote command results:\n%s", strings.Join(results, "\n"))
	}()

	run("info", "info")
	run("dns", "dns")
	run("dns rootzones", "dns", "rootzones")
	run("ca list", "ca", "list")
	run("ca get", "ca", "get", caID)
	run("crt list all", "crt", "list")
	run("crt list ca", "crt", "list", "--ca", caID)

	claimArgs := []string{"crt", "claim", caID, "--name", certName}
	if autodnsIPv4 != "" {
		claimArgs = append(claimArgs, "--autodns-ipv4", autodnsIPv4)
	}
	run("crt claim", claimArgs...)
	run("crt get ca", "crt", "get", "--ca", caID, certName)
	run("crt get all ca", "crt", "get", certName)

	certPEM := run("pem crt", "crt", "pem", caID, certName, "crt")
	keyPEM := run("pem key", "crt", "pem", caID, certName, "key")
	run("pem chain", "crt", "pem", caID, certName, "chain")
	run("pem root", "crt", "pem", caID, certName, "root")
	run("pem rootchain", "crt", "pem", caID, certName, "rootchain")
	run("pem fullchain", "crt", "pem", caID, certName, "fullchain")
	run("pem all", "crt", "pem", caID, certName)
	matches, err := CertificateMatchesKey([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("certificate/key match check failed: %v", err)
	}
	if !matches {
		t.Fatal("downloaded certificate does not match downloaded key")
	}
	results = append(results, "PASS certificate/key match")

	deleteClaimArgs := []string{"crt", "claim", caID, "--name", deleteCertName}
	if autodnsIPv4 != "" {
		deleteClaimArgs = append(deleteClaimArgs, "--autodns-ipv4", autodnsIPv4)
	}
	run("crt claim for ca delete", deleteClaimArgs...)
	run("crt delete ca", "crt", "delete", "--ca", caID, deleteCertName)
	run("crt delete all ca", "crt", "delete", certName)
}

func executeRemoteCommand(args ...string) (string, string, error) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := NewRootCommand(&out, &errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}
