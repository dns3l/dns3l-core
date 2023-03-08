package clitypes

import (
	"fmt"
	"os"
	"time"
)

type LoginDNSType struct {
	Verbose      bool
	DNSBackend   string
	FromTerminal bool
	ForceOStream bool
	User         string
	Password     string
}

func (loginData *LoginDNSType) Init(verbose bool, backend string, user string, pass string, forceOStream bool, fromTerminal bool) {
	loginData.Verbose = verbose
	loginData.DNSBackend = backend
	// providerID = User Name
	loginData.User = user
	loginData.Password = pass
	loginData.FromTerminal = fromTerminal
	loginData.ForceOStream = forceOStream
}

func (loginData *LoginDNSType) PrintParams() {
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "INFO: login DNS called \n")
		fmt.Fprintf(os.Stderr, "INFO: Secret from terminal '%v' \n", loginData.FromTerminal)
		fmt.Fprintf(os.Stderr, "INFO: DNS backend %s\n", loginData.DNSBackend)
		fmt.Fprintf(os.Stderr, "INFO: user %s\n", loginData.User)
		fmt.Fprintf(os.Stderr, "INFO: password %s\n", loginData.Password)
		var user, pass string
		user, pass = getProviderData(loginData.DNSBackend, false)
		fmt.Fprintf(os.Stderr, "INFO: Backend User %s\n", user)
		fmt.Fprintf(os.Stderr, "INFO: Backend password %s\n", pass)
	}
}

func (loginData *LoginDNSType) CheckParams() error {
	if !loginData.FromTerminal {
		if loginData.Password == "NOT_SET" {
			_, pass := getProviderData(loginData.DNSBackend, loginData.Verbose)
			if pass == "" {
				return NewValueError(510, fmt.Errorf("no DNS backend Password provided \n  use --terminal=XXXX or  $(DNS3L_DNS_SECRET) or config to provide one"))
			}
		}
	}
	return nil
}

func (loginData *LoginDNSType) DoCommand() error {
	var secret string
	var user string
	var bIn []byte
	var inErr error
	if loginData.FromTerminal {
		bIn, inErr = GetPasswordFromConsole("DNS Provider Login Secret " + loginData.User + " =")
		if inErr == nil {
			secret = string(bIn)
		} else {
			return NewValueError(520, fmt.Errorf("DNS get password from terminal failed, %v", inErr.Error()))
		}
	} else {
		switch {
		case loginData.Password == "NOT_SET":
			_, secret = getProviderData(loginData.DNSBackend, false)
		default:
			secret = loginData.Password
		}
	}
	switch {
	case loginData.User == "NOT_SET":
		user, _ = getProviderData(loginData.DNSBackend, false)
	default:
		user = loginData.User
		if loginData.Verbose {
			fmt.Fprintf(os.Stderr, "Override backend user due to ENV/CLI option:\n")
		}
	}
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "KeyRing name %v\n", user)
	}
	if nil != CachePassword(user, secret, 3600*4, loginData.Verbose) {
		return NewValueError(530, fmt.Errorf("can not store secrete in the password safe"))
	}
	time.Sleep(time.Millisecond * 10)
	_, inErr = GetPasswordfromRing(user, loginData.Verbose)
	if inErr != nil {
		return NewValueError(540, fmt.Errorf("write to password safe was not OK: Error %v", inErr.Error()))
	}
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "Info: DNS backend login Secret sucessfully stored in password safe '%v' \n", user)
	}
	return nil
}
