package types

//Can spawn a new instance of a DNS provider.
//Provider-specific config is unmarshaled into the builder's implementing struct.
type CAProviderBuilder interface {
	NewInstance() (CAProvider, error)
}

type CAProviderInfo struct {
	Name        string
	Description string
	LogoPath    string
	URL         string
	Roots       string
	Type        string
	IsAcme      bool
}

type CAProvider interface {
	GetInfo() *CAProviderInfo
	GetTotalValid() int
	GetTotalIssued() int
	IsEnabled() bool
}
