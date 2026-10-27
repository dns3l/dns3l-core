package util

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

const healthCheckTimeout = 5 * time.Second

type Health struct {
	Healthy  bool
	Endpoint string
	Message  string
}

type HealthCheckable interface {
	GetHealth() Health
}

type MultiHealthCheckable interface {
	GetHealth() map[string]Health
}

func CheckHealth(checks ...HealthCheck) (bool, error) {
	for _, check := range checks {
		healthy, err := check()
		if err != nil {
			return false, err
		}
		if !healthy {
			return false, nil
		}
	}
	return true, nil
}

type HealthCheck func() (bool, error)

func getHostPortFrom(hostnameOrURL string) (host, port string) {
	u, err := url.Parse(hostnameOrURL)
	if err == nil && u.Host != "" {
		hostnameOrURL = u.Host
	}
	host, port, err = net.SplitHostPort(hostnameOrURL)
	if err == nil {
		return host, port
	}
	if u.Host == "" {
		return hostnameOrURL, "80"
	}
	host = u.Host
	switch u.Scheme {
	case "https":
		return host, "443"
	default:
		return host, "80"
	}
}

func CheckDNSResolution(hostnameOrURL string) HealthCheck {
	return func() (bool, error) {
		host, _ := getHostPortFrom(hostnameOrURL)
		// If Host is IP address, skip DNS resolution check
		if net.ParseIP(host) != nil {
			return true, nil
		}
		_, err := net.LookupHost(host)
		if err != nil {
			return false, fmt.Errorf("dns resolution failed for %s: %w", hostnameOrURL, err)
		}
		return true, nil
	}
}

func CheckTCPConnection(hostnameOrURL string) HealthCheck {
	return func() (bool, error) {
		host, port := getHostPortFrom(hostnameOrURL)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), healthCheckTimeout)
		if err != nil {
			return false, fmt.Errorf("tcp connection check failed for %s: %w", hostnameOrURL, err)
		}
		//nolint:errcheck // ignore error on close, since we are only checking connectivity
		defer conn.Close()
		return true, nil
	}
}

func CheckTLSConnection(hostnameOrURL string, insecureSkipVerify bool) HealthCheck {
	return func() (bool, error) {
		host, port := getHostPortFrom(hostnameOrURL)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), healthCheckTimeout)
		if err != nil {
			return false, fmt.Errorf("tls connection check failed for %s: %w", hostnameOrURL, err)
		}
		//nolint:errcheck // ignore error on close, since we are only checking connectivity
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			ServerName:         host,
		})
		err = tlsConn.Handshake()
		if err != nil {
			return false, fmt.Errorf("tls handshake failed for %s: %w", hostnameOrURL, err)
		}
		return true, nil
	}
}

func CheckDNSServer(hostPort string, hostNames ...string) HealthCheck {
	return func() (bool, error) {
		for _, hostName := range hostNames {
			m := new(dns.Msg)
			m.SetQuestion(hostName, dns.TypeA)

			_, err := dns.Exchange(m, hostPort)
			if err != nil {
				return false, fmt.Errorf("dns server check failed for %s: %w", hostPort, err)
			}
		}
		return true, nil
	}
}
