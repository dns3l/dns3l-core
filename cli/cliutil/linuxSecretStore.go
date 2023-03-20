//go:build linux && (amd64 || arm)
// +build linux
// +build amd64 arm

package cliutil

import (
	"fmt"
	"os"
	"syscall"

	"github.com/jsipprell/keyctl"
	"golang.org/x/term"
)

// CachePassword - Saves a secret to the User Session Keyring.
// It will cache the secret for a given number of seconds.
// To invalidate a password, save it with a 1 second timeout.
func CachePassword(name, password string, timeoutSeconds uint, verbose bool) error {
	// Create session
	if password == "" {
		return fmt.Errorf("function cachePassword(): name:%s empty secret", name)
	}
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return fmt.Errorf("function cachePassword(): name:%s couldn't create keyring session: %v", name, err)
	}
	// Store key
	keyring.SetDefaultTimeout(timeoutSeconds)
	key, err := keyring.Add(name, []byte(password))
	if err != nil {
		return fmt.Errorf("function cachePassword(): name:%s couldn't store '%s'", name, err)
	}
	// OK case
	if verbose {
		info, _ := key.Info()
		fmt.Fprintf(os.Stderr, "Function CachePassword():name:%s key: %+v\n", name, info)
	}
	return nil
}

func GetPasswordfromRing(name string, verbose bool) ([]byte, error) {
	// Create session
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return nil, fmt.Errorf("function getPasswordfromRing(): couldn't create keyring session: %v", err)
	}
	// Retrieve
	key, err := keyring.Search(name)
	if err == nil {
		data, err := key.Get()
		if err != nil {
			return nil, fmt.Errorf("function getPasswordfromRing(): couldn't retrieve key data: %v", err)
		}
		if verbose {
			info, _ := key.Info()
			fmt.Fprintf(os.Stderr, "INFO Function GetPasswordfromRing() key: %+v\n", info)
		}
		return data, nil
	}
	return nil, fmt.Errorf("function getPasswordfromRing(): couldn't find key data: %v", err)
}

// GetPassword - Gets a secret from the User Session Keyring.
// If the key doesn't exist, it asks the user to enter the password value.
// It will cache the secret for a given number of seconds.
func GetPasswordFromConsole(name string) ([]byte, error) {
	fmt.Printf("Enter password for '%s': ", name)
	password, err := term.ReadPassword(int(syscall.Stdin))
	// 55 space to override
	fmt.Printf("\r                                                             \r")
	if err != nil {
		return nil, fmt.Errorf("function getPasswordFromConsole(): failed to read password: %v", err)
	}
	return password, nil
}
