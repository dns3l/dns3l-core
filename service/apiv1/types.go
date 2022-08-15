package apiv1

type ServerInfo struct {
	Version *ServerInfoVersion `json:"version"`
	Contact *ServerInfoContact `json:"contact"`
}

type ServerInfoVersion struct {
	Daemon string `json:"daemon"`
	API    string `json:"api"`
}

type ServerInfoContact struct {
	URL   string   `json:"url"`
	EMail []string `json:"email"`
}

type DNSHandlerInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Feature     []string `json:"feature"`
	ZoneNesting bool     `json:"zoneNesting"`
}

type DNSRootzoneInfo struct {
	Root    string   `json:"root"`
	AutoDNS string   `json:"autodns"`
	AcmeDNS string   `json:"acmedns"`
	CA      []string `json:"ca"`
}

type CAInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"desc"`
	LogoPath    string   `json:"logo"`
	URL         string   `json:"url"`
	Roots       string   `json:"roots"`
	TotalValid  uint     `json:"totalValid"`
	TotalIssued uint     `json:"totalIssued"`
	Type        string   `json:"type"`
	IsAcme      bool     `json:"acme"`
	Rootzones   []string `json:"rtzn"`
	Enabled     bool     `json:"enabled"`
}

type AutoDNSInfo struct {
	IPv4 string `json:"ipv4" validate:"required,ipv4"`
}

type CertClaimInfo struct {
	Name            string       `json:"name" validate:"required,fqdn"`
	Wildcard        bool         `json:"wildcard"`
	SubjectAltNames []string     `json:"san" validate:"dive,required,fqdn|fqdnWildcard"`
	AutoDNS         *AutoDNSInfo `json:"autodns"`
	Hints           interface{}  `json:"hints"`
}

type CertResources struct {
	Certificate string `json:"cert"`
	Key         string `json:"key"`
	Chain       string `json:"chain"`
	FullChain   string `json:"fullchain"`
}

type CertInfo struct {
	Name      string `json:"name"`
	ClaimedBy struct {
		Name  string `json:"name"`
		EMail string `json:"email"`
	} `json:"claimedBy"`
	ClaimedOn  string `json:"claimedOn"`
	ValidTo    string `json:"validTo"`
	Valid      bool   `json:"valid"`
	RenewCount uint   `json:"renewCount"`
	Wildcard   bool   `json:"wildcard"`
	SubjectCN  string `json:"subjectCN"`
	IssuerCN   string `json:"issuerCN"`
	Serial     string `json:"serial"`
}
