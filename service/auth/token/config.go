package token

type TokenAuthConfig struct {
	Static []Token `yaml:"static"`
}

type Token struct {
	Name           string   `yaml:"name" validate:"required"`
	Plain          string   `yaml:"plain"`
	Sha256         string   `yaml:"sha256"`
	Write          bool     `yaml:"write"`
	DomainsAllowed []string `yaml:"domainsallowed"`
}
