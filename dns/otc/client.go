package otc

import (
	"errors"

	"github.com/huaweicloud/golangsdk"
	huaweisdk "github.com/huaweicloud/golangsdk/openstack"
)

// AKSKOptionsFromEnv configures the OTC/OpenStack client to use AK/SK authentication,
// takes any auth information / configuration from the environment
func (p *DNSProvider) akskOptionsFromConfig() (golangsdk.AKSKAuthOptions, error) {

	var nilAKSKOptions = golangsdk.AKSKAuthOptions{}

	c := p.c

	authURL := c.Auth.AuthURL
	ak := c.Auth.AccessKey
	sk := c.Auth.SecretKey

	if authURL == "" {
		err := errors.New("missing authURL")
		return nilAKSKOptions, err
	}

	if ak == "" {
		err := errors.New("missing AccessKey")
		return nilAKSKOptions, err
	}

	if sk == "" {
		err := errors.New("missing SecretKey")
		return nilAKSKOptions, err
	}

	akskOptions := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: authURL,
		AccessKey:        ak,
		SecretKey:        sk,
		ProjectId:        c.Auth.ProjectName,
		ProjectName:      c.Auth.ProjectID,
	}

	return akskOptions, nil
}

// Auth returns an env-authenticated OpenStack client
func (p *DNSProvider) Auth() (*golangsdk.ProviderClient, error) {

	opts, err := p.akskOptionsFromConfig()
	if err != nil {
		return nil, err
	}

	client, err := huaweisdk.NewClient(opts.GetIdentityEndpoint())
	if err != nil {
		return nil, err
	}

	err = huaweisdk.Authenticate(client, opts)
	if err != nil {
		return nil, err
	}

	return client, nil

}
