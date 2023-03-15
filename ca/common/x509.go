package common

type PEMResource struct {
	PEMData     string
	ContentType string
	Domains     []string
	CanBePublic bool
}
