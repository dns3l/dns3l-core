package cli

import appctx "github.com/dns3l/dns3l-core/context"

// ImplementedAPIVersion is the OpenAPI specification version implemented by dns3lcli.
const ImplementedAPIVersion = "1.2.0"

func userAgent() string {
	return "dns3lcli/" + appctx.ServiceVersion + " dns3l-api/" + ImplementedAPIVersion
}
