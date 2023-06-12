//go:build windows && (amd64 || arm)
// +build windows
// +build amd64 arm

package cliutil

import (
	"fmt"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
	"os"
	"syscall"
)

// CachePassword - Saves a secret to the User Session Keyring.
// It will cache the secret for a given number of seconds.
// To invalidate a password, save it with a 1 second timeout.
func CachePassword(name, password string, timeoutSeconds uint, verbose bool) error {
	// Create session
	if password == "" {
		return fmt.Errorf("function cachePassword(): name:%s empty secret", name)
	}
	err := keyring.Set("dns3l", name, password)
	if err != nil {
		return fmt.Errorf("function cachePassword(): name:%s couldn't store '%s'", name, err)
	}
	// OK case
	if verbose {
		fmt.Fprintf(os.Stderr, "Function CachePassword():name:%s service: dns3l \n", name)
	}
	return nil
}

func GetPasswordfromRing(name string, verbose bool) ([]byte, error) {
	// Create session
	// Retrieve
	data, err := keyring.Get("dns3l", name)
	if err != nil {
		return nil, fmt.Errorf("function getPasswordfromRing(): couldn't retrieve key data: %v", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "INFO Function GetPasswordfromRing() key: dns3l %+v\n", name)
	}
	return []byte(data), nil
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
