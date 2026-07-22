package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
	appctx "github.com/dns3l/dns3l-core/context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CommandFactory struct {
	Out    io.Writer
	ErrOut io.Writer
	Client func(*RuntimeConfig) *Client

	opts FlagOptions
}

func NewRootCommand(out, errOut io.Writer) *cobra.Command {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	f := &CommandFactory{
		Out:    out,
		ErrOut: errOut,
		Client: NewClient,
		opts: FlagOptions{
			ConfigPath:         DefaultConfigPath,
			OIDCDaemonClientID: DefaultDaemonOIDCClient,
			Timeout:            DefaultTimeout,
			TimeoutClaim:       DefaultClaimTimeout,
		},
	}
	return f.newRootCommand()
}

func Execute() error {
	cmd := NewRootCommand(os.Stdout, os.Stderr)
	return cmd.Execute()
}

func (f *CommandFactory) newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "dns3lcli",
		Short:         "Command-line client for dns3ld",
		Long:          rootLongHelp(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			level := log.WarnLevel
			if f.opts.Debug {
				level = log.DebugLevel
			}
			if f.opts.Trace {
				level = log.TraceLevel
			}
			log.SetOutput(f.ErrOut)
			log.SetLevel(level)
		},
	}
	root.SetOut(f.Out)
	root.SetErr(f.ErrOut)
	root.PersistentFlags().StringVarP(&f.opts.ConfigPath, "config", "c", DefaultConfigPath, "YAML config path (env: DNS3L_CONFIG)")
	root.PersistentFlags().StringVar(&f.opts.Server, "server", "", "DNS3L API URL, for example https://example.com/api/v1 (config: server (aliases: instance, dns3l_instance); env: DNS3L_SERVER (alias: DNS3L_INSTANCE))")
	root.PersistentFlags().StringVar(&f.opts.ADUser, "ad-user", "", "AD user for OIDC password grant (config: ad_user; env: DNS3L_AD_USER)")
	root.PersistentFlags().StringVar(&f.opts.ADPassword, "ad-password", "", "AD password for OIDC password grant (config: ad_password (alias: ad_pass); env: DNS3L_AD_PASSWORD (alias: DNS3L_AD_PASS))")
	root.PersistentFlags().StringVar(&f.opts.OIDCClientID, "oidc-client-id", "", "OIDC client ID used to fetch tokens (config: oidc_client_id (alias: client_id); env: DNS3L_OIDC_CLIENT_ID (aliases: OIDC_CLIENT_ID, CLIENT_ID))")
	root.PersistentFlags().StringVar(&f.opts.OIDCClientSecret, "oidc-client-secret", "", "OIDC client secret used to fetch tokens (config: oidc_client_secret (alias: client_secret); env: DNS3L_OIDC_CLIENT_SECRET (aliases: OIDC_CLIENT_SECRET, CLIENT_SECRET))")
	root.PersistentFlags().StringVar(&f.opts.OIDCDaemonClientID, "oidc-daemon-client-id", DefaultDaemonOIDCClient, "OIDC audience daemon client ID (config: oidc_daemon_client_id; env: DNS3L_OIDC_DAEMON_CLIENT_ID (alias: DAEMON_CLIENT_ID))")
	root.PersistentFlags().StringVar(&f.opts.Token, "token", "", "manually fetched OIDC ID token (config: token; env: DNS3L_ID_TOKEN (alias: DNS3L_TOKEN))")
	root.PersistentFlags().StringVar(&f.opts.APIKey, "api-key", "", "DNS3L static API key (config: api_key; env: DNS3L_API_KEY)")
	root.PersistentFlags().BoolVar(&f.opts.NoAuth, "no-auth", false, "do not send authentication")
	root.PersistentFlags().BoolVar(&f.opts.JSON, "json", false, "print raw JSON responses")
	root.PersistentFlags().BoolVar(&f.opts.Debug, "debug", false, "write debug logs to stderr")
	root.PersistentFlags().BoolVar(&f.opts.Trace, "trace", false, "write trace logs to stderr")
	root.PersistentFlags().DurationVar(&f.opts.Timeout, "timeout", DefaultTimeout, "HTTP timeout (config: timeout; env: DNS3L_TIMEOUT)")
	root.PersistentFlags().DurationVar(&f.opts.TimeoutClaim, "timeout-claim", DefaultClaimTimeout, "HTTP timeout for certificate claims (config: timeout_claim; env: DNS3L_TIMEOUT_CLAIM)")

	root.AddCommand(f.newInfoCommand())
	root.AddCommand(f.newDNSCommand())
	root.AddCommand(f.newCACommand())
	root.AddCommand(f.newCRTCommand())
	root.AddCommand(f.newVersionCommand())
	return root
}

func rootLongHelp() string {
	return `Command-line client for dns3ld, version ` + appctx.ServiceVersion + ` (implemented API version ` + ImplementedAPIVersion + `)

Configuration:
  dns3lcli reads ./config.yaml by default. Override the path with --config or DNS3L_CONFIG.
  Values are resolved in this order: command-line flags, environment variables, config file.
  Config keys and environment variables are shown inline with the corresponding flags below.

Example config.yaml:
  server: https://my-server.com/api/v1
  ad_user: alice@example.com
  ad_password: change-me
  oidc_client_id: dns3l-api
  oidc_client_secret: change-me
  oidc_daemon_client_id: dns3ld
  token: eyJ...
  api_key: ...
  timeout: 60s
  timeout_claim: 10m

Required for OIDC-authenticated calls unless --token, --api-key, --no-auth, or anonymous access is used:
  server (aliases: instance, dns3l_instance), ad_user, ad_password (alias: ad_pass),
  oidc_client_id (alias: client_id), oidc_client_secret (alias: client_secret)`
}

func (f *CommandFactory) newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print dns3lcli and implemented API versions",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(f.Out, "dns3lcli version: %s\nAPI version: %s\n", appctx.ServiceVersion, ImplementedAPIVersion)
			return err
		},
	}
}

func (f *CommandFactory) newInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show server information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.runJSONCommand(cmd, false, http.MethodGet, "/info", nil, nil, func(resp *Response, color bool) error {
				info, err := DecodeJSON[apiv1.ServerInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintInfo(f.Out, info, color)
			})
		},
	}
}

func (f *CommandFactory) newDNSCommand() *cobra.Command {
	dnsCmd := &cobra.Command{
		Use:   "dns",
		Short: "Show DNS provider information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.runJSONCommand(cmd, false, http.MethodGet, "/dns", nil, nil, func(resp *Response, color bool) error {
				handlers, err := DecodeJSON[[]apiv1.DNSHandlerInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintDNSHandlers(f.Out, handlers, color)
			})
		},
	}
	dnsCmd.AddCommand(&cobra.Command{
		Use:   "rootzones",
		Short: "Show DNS root zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.runJSONCommand(cmd, false, http.MethodGet, "/dns/rtzn", nil, nil, func(resp *Response, color bool) error {
				rootzones, err := DecodeJSON[[]apiv1.DNSRootzoneInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintDNSRootzones(f.Out, rootzones, color)
			})
		},
	})
	return dnsCmd
}

func (f *CommandFactory) newCACommand() *cobra.Command {
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Show certificate authority information",
	}
	caCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List CAs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.runJSONCommand(cmd, false, http.MethodGet, "/ca", nil, nil, func(resp *Response, color bool) error {
				cas, err := DecodeJSON[[]apiv1.CAInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintCAs(f.Out, cas, color)
			})
		},
	})
	caCmd.AddCommand(&cobra.Command{
		Use:   "get <ca-id>",
		Short: "Show one CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.runJSONCommand(cmd, false, http.MethodGet, "/ca/"+pathEscape(args[0]), nil, nil, func(resp *Response, color bool) error {
				ca, err := DecodeJSON[apiv1.CAInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintCA(f.Out, ca, color)
			})
		},
	})
	return caCmd
}

func (f *CommandFactory) newCRTCommand() *cobra.Command {
	crtCmd := &cobra.Command{
		Use:     "crt",
		Aliases: []string{"cert"},
		Short:   "Manage certificates",
	}
	crtCmd.AddCommand(f.newCRTListCommand())
	crtCmd.AddCommand(f.newCRTGetCommand())
	crtCmd.AddCommand(f.newCRTClaimCommand())
	crtCmd.AddCommand(f.newCRTDeleteCommand())
	crtCmd.AddCommand(f.newCRTPemCommand())
	return crtCmd
}

func (f *CommandFactory) newCRTListCommand() *cobra.Command {
	var caID string
	var limit uint64
	var offset uint64
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/crt"
			if caID != "" {
				path = "/ca/" + pathEscape(caID) + "/crt"
			}
			query := url.Values{}
			if limit > 0 {
				query.Add("limit", strconv.FormatUint(limit, 10))
			}
			if offset > 0 {
				query.Add("offset", strconv.FormatUint(offset, 10))
			}
			return f.runJSONCommand(cmd, false, http.MethodGet, path, query, nil, func(resp *Response, color bool) error {
				certs, err := DecodeJSON[[]apiv1.CertInfo](resp.Body)
				if err != nil {
					return err
				}
				return PrintCerts(f.Out, paginationInfo(resp.Headers), certs, color)
			})
		},
	}
	cmd.Flags().StringVar(&caID, "ca", "", "limit to a CA ID")
	cmd.Flags().Uint64Var(&limit, "limit", 0, "maximum number of entries to list (0 means infinite)")
	cmd.Flags().Uint64Var(&offset, "offset", 0, "number of matching items to skip")
	return cmd
}

func paginationInfo(header http.Header) string {
	offset := strToUint64_0(header.Get("Page-Offset"), "offset")
	limit := strToUint64_0(header.Get("Page-Limit"), "limit")
	totalcount := strToUint64_0(header.Get("Total-Count"), "totalcount")
	if limit > 0 {
		return fmt.Sprintf("Showing element %d - %d of %d elements", offset+1, offset+limit, totalcount)
	}
	return ""
}

func strToUint64_0(s, desc string) uint64 {
	if s == "" {
		return 0
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		log.WithFields(log.Fields{"desc": desc, "value": s}).Debug("could not parse unsigned integer, assuming 0")
		return 0
	}
	return u
}

func (f *CommandFactory) newCRTGetCommand() *cobra.Command {
	var caID string
	cmd := &cobra.Command{
		Use:   "get <crt-name>",
		Short: "Show certificate metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := pathEscape(args[0])
			path := "/crt/" + name
			if caID != "" {
				path = "/ca/" + pathEscape(caID) + "/crt/" + name
			}
			return f.runCRTGetCommand(cmd, path, caID != "", args[0])
		},
	}
	cmd.Flags().StringVar(&caID, "ca", "", "CA ID")
	return cmd
}

func (f *CommandFactory) runCRTGetCommand(cmd *cobra.Command, path string, caScoped bool, certName string) error {
	cfg, err := f.runtimeConfig(cmd, false)
	if err != nil {
		return err
	}
	resp, err := f.Client(cfg).Do(cmd.Context(), http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if caScoped {
		if cfg.JSON {
			return WriteJSON(f.Out, resp.Body)
		}
		cert, err := DecodeJSON[apiv1.CertInfo](resp.Body)
		if err != nil {
			return err
		}
		return PrintCert(f.Out, cert, SupportsColor(os.Stdout))
	}
	if cfg.JSON {
		body, err := singleCertJSONFromList(resp.Body, certName)
		if err != nil {
			return err
		}
		return WriteJSON(f.Out, body)
	}
	cert, err := singleCertInfoFromList(resp.Body, certName)
	if err != nil {
		return err
	}
	return PrintCert(f.Out, cert, SupportsColor(os.Stdout))
}

func singleCertJSONFromList(body []byte, certName string) ([]byte, error) {
	certs, err := DecodeJSON[[]json.RawMessage](body)
	if err != nil {
		return nil, err
	}
	if err := requireSingleCert(certName, len(certs)); err != nil {
		return nil, err
	}
	return certs[0], nil
}

func singleCertInfoFromList(body []byte, certName string) (apiv1.CertInfo, error) {
	certs, err := DecodeJSON[[]apiv1.CertInfo](body)
	if err != nil {
		return apiv1.CertInfo{}, err
	}
	if err := requireSingleCert(certName, len(certs)); err != nil {
		return apiv1.CertInfo{}, err
	}
	return certs[0], nil
}

func requireSingleCert(certName string, count int) error {
	switch count {
	case 0:
		return fmt.Errorf("certificate %q not found", certName)
	case 1:
		return nil
	default:
		return fmt.Errorf("multiple certificate entries found for %q; use --ca to disambiguate", certName)
	}
}

func (f *CommandFactory) newCRTClaimCommand() *cobra.Command {
	claim := apiv1.CertClaimInfo{}
	var san []string
	var autodnsIPv4 string
	cmd := &cobra.Command{
		Use:   "claim <ca-id> <name>",
		Short: "Claim a certificate from an ACME CA",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			claim.Name = args[1]
			claim.SubjectAltNames = san
			if autodnsIPv4 != "" {
				claim.AutoDNS = &apiv1.AutoDNSInfo{IPv4: autodnsIPv4}
			}
			path := "/ca/" + pathEscape(args[0]) + "/crt"
			return f.runSlowCommand(cmd, true, http.MethodPost, path, nil, claim)
		},
	}
	cmd.Flags().BoolVar(&claim.Wildcard, "wildcard", false, "claim wildcard certificate")
	cmd.Flags().StringArrayVar(&san, "san", nil, "subject alternative name; repeatable")
	cmd.Flags().StringVar(&autodnsIPv4, "autodns-ipv4", "", "AutoDNS IPv4 address")
	cmd.Flags().Uint16Var(&claim.Hints.TTL, "ttl", 0, "certificate TTL hint in days")
	return cmd
}

func (f *CommandFactory) newCRTDeleteCommand() *cobra.Command {
	var caID string
	cmd := &cobra.Command{
		Use:   "delete <crt-name>",
		Short: "Delete a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := pathEscape(args[0])
			path := "/crt/" + name
			if caID != "" {
				path = "/ca/" + pathEscape(caID) + "/crt/" + name
			}
			return f.runJSONCommand(cmd, true, http.MethodDelete, path, nil, nil, func(resp *Response, _ bool) error {
				if len(strings.TrimSpace(string(resp.Body))) > 0 {
					return PrintGenericJSON(f.Out, resp.Body, false)
				}
				_, err := fmt.Fprintln(f.Out, "deleted")
				return err
			})
		},
	}
	cmd.Flags().StringVar(&caID, "ca", "", "CA ID")
	return cmd
}

func (f *CommandFactory) newCRTPemCommand() *cobra.Command {
	var output string
	var outputDir string
	var noCheck bool
	var resource string
	cmd := &cobra.Command{
		Use:   "pem <ca-id> <crt-name>",
		Short: "Download PEM-encoded certificate resources",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/ca/" + pathEscape(args[0]) + "/crt/" + pathEscape(args[1]) + "/pem"
			if resource != "" {
				if !validPEMResource(resource) {
					return fmt.Errorf("unknown PEM resource %q", resource)
				}
				if outputDir != "" {
					return errors.New("--output-dir can only be used when downloading all PEM resources")
				}
				path += "/" + pathEscape(resource)
				return f.runPEMSingle(cmd, path, output, !noCheck, resource == "key")
			}
			if output != "" {
				return errors.New("--output can only be used when downloading one PEM resource")
			}
			return f.runPEMAll(cmd, path, outputDir, !noCheck)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "write one PEM resource to this file")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "write all PEM resources to this directory")
	cmd.Flags().BoolVar(&noCheck, "no-pem-check", false, "disable PEM format validation")
	cmd.Flags().StringVarP(&resource, "resource", "r", "", "download a single PEM resource (crt|key|chain|root|rootchain|fullchain) instead of all")
	return cmd
}

func (f *CommandFactory) runJSONCommand(cmd *cobra.Command, requireAuth bool, method, path string, query url.Values, body any, print func(*Response, bool) error) error {
	cfg, err := f.runtimeConfig(cmd, requireAuth)
	if err != nil {
		return err
	}
	resp, err := f.Client(cfg).Do(cmd.Context(), method, path, query, body)
	if err != nil {
		return err
	}
	if cfg.JSON {
		return WriteJSON(f.Out, resp.Body)
	}
	return print(resp, SupportsColor(os.Stdout))
}

func (f *CommandFactory) runSlowCommand(cmd *cobra.Command, requireAuth bool, method, path string, query url.Values, body any) error {
	cfg, err := f.runtimeConfig(cmd, requireAuth)
	if err != nil {
		return err
	}
	cfg.Timeout = cfg.TimeoutClaim
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
		})
	}
	go progress(f.ErrOut, done)
	resp, err := f.Client(cfg).Do(cmd.Context(), method, path, query, body)
	stop()
	_, _ = fmt.Fprintln(f.ErrOut)
	if err != nil {
		return err
	}
	if cfg.JSON {
		return WriteJSON(f.Out, resp.Body)
	}
	_, err = fmt.Fprintln(f.Out, "certificate claim completed")
	return err
}

func (f *CommandFactory) runPEMSingle(cmd *cobra.Command, path string, output string, check bool, requireAuth bool) error {
	cfg, err := f.runtimeConfig(cmd, requireAuth)
	if err != nil {
		return err
	}
	resp, err := f.Client(cfg).Do(cmd.Context(), http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if check {
		if err := ValidatePEM(resp.Body); err != nil {
			return err
		}
	}
	if output != "" {
		return WritePEMFile(output, resp.Body, false)
	}
	_, err = f.Out.Write(resp.Body)
	if err != nil {
		return err
	}
	if len(resp.Body) > 0 && resp.Body[len(resp.Body)-1] != '\n' {
		_, err = fmt.Fprintln(f.Out)
		return err
	}
	return nil
}

func (f *CommandFactory) runPEMAll(cmd *cobra.Command, path string, outputDir string, check bool) error {
	cfg, err := f.runtimeConfig(cmd, true)
	if err != nil {
		return err
	}
	resp, err := f.Client(cfg).Do(cmd.Context(), http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if cfg.JSON {
		return WriteJSON(f.Out, resp.Body)
	}
	resources, err := DecodeJSON[apiv1.CertResources](resp.Body)
	if err != nil {
		return err
	}
	if outputDir != "" {
		if err := WritePEMDirectory(outputDir, resources, check); err != nil {
			return err
		}
		_, err := fmt.Fprintf(f.Out, "wrote PEM resources to %s\n", outputDir)
		return err
	}
	return PrintCertResources(f.Out, resources, check, SupportsColor(os.Stdout))
}

func (f *CommandFactory) runtimeConfig(cmd *cobra.Command, requireAuth bool) (*RuntimeConfig, error) {
	cfg, err := ResolveConfig(f.opts, changedFlags(cmd), requireAuth)
	if err != nil {
		return nil, err
	}
	if requireAuth || cfg.NoAuth {
		return cfg, nil
	}
	if cfg.hasDirectAuth() || cfg.hasCompleteOIDCAuth() {
		return cfg, nil
	}
	if cfg.hasPartialOIDCAuth() {
		return nil, fmt.Errorf("incomplete authentication setting(s): %s", strings.Join(missingAuthFields(cfg), ", "))
	}
	if !requireAuth {
		cfg.NoAuth = true
	}
	return cfg, nil
}

func changedFlags(cmd *cobra.Command) ChangedFlags {
	changed := ChangedFlags{}
	for c := cmd; c != nil; c = c.Parent() {
		c.Flags().VisitAll(func(flag *pflag.Flag) {
			if flag.Changed {
				changed[flag.Name] = true
			}
		})
		c.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
			if flag.Changed {
				changed[flag.Name] = true
			}
		})
	}
	return changed
}

func progress(out io.Writer, done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	_, _ = fmt.Fprint(out, "certificate claim in progress")
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_, _ = fmt.Fprint(out, ".")
		}
	}
}

func validPEMResource(resource string) bool {
	for _, allowed := range []string{"crt", "key", "chain", "root", "rootchain", "fullchain"} {
		if resource == allowed {
			return true
		}
	}
	return false
}
