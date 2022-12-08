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

func (loginData *LoginDNSType) CheckParams() bool {
	OK := true
	if !loginData.FromTerminal {
		if loginData.Password == "NOT_SET" {
			_, pass := getProviderData(loginData.DNSBackend, loginData.Verbose)
			if pass == "" {
				OK = false
				fmt.Fprintf(os.Stderr, "ERROR: No DNS backend Password provided \n  use --terminal=XXXX or  $(DNS3L_DNS_SECRET) or config to provide one\n")
			}
		}
		// || loginData.Password == ""
	}
	return OK
}

func (loginData *LoginDNSType) DoCommand() {
	var secret string
	var user string
	var bIn []byte
	var inErr error
	if loginData.FromTerminal {
		bIn, inErr = GetPasswordFromConsole("DNS Provider Login Secret " + loginData.User + " =")
		if inErr == nil {
			secret = string(bIn)
		} else {
			fmt.Fprintf(os.Stderr, "ERROR: store login DNS data:  %v \nt", inErr)
			return
		}
	} else {
		// TOBE DONE
		switch {
		case loginData.Password == "NOT_SET":
			_, secret = getProviderData(loginData.DNSBackend, false)
		default:
			secret = loginData.Password
			fmt.Fprintf(os.Stderr, "Override backend secret due to ENV/CLI option:\n")
		}
	}
	switch {
	case loginData.User == "NOT_SET":
		user, _ = getProviderData(loginData.DNSBackend, false)
	default:
		user = loginData.User
		fmt.Fprintf(os.Stderr, "Override backend user due to ENV/CLI option:\n")
	}
	if nil != CachePassword(user, secret, 3600*4, loginData.Verbose) {
		fmt.Fprintf(os.Stderr, "ERROR store login data of DNS backend, can not store data in the tresor\n")
		return
	}
	time.Sleep(time.Millisecond * 10)
	_, inErr = GetPasswordfromRing(user, loginData.Verbose)
	if inErr != nil {
		fmt.Fprintf(os.Stderr, "ERROR: store login data of DNS backend, write to tresor was not OK: Error occured %v", inErr)
		return
	}
	if loginData.Verbose {
		fmt.Fprintf(os.Stderr, "Info: DNS backend login Secret sucessfully stored in tresor '%v' \n", user)
	}
}
