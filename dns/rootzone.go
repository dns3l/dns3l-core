package dns

type RootZone struct {
	Root           string   `yaml:"root"`
	DNSProvAutoDNS string   `yaml:"autodns"`
	DNSProvAcme    string   `yaml:"acmedns"`
	CAs            []string `yaml:"ca"`
}
