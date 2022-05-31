package common

import (
	"errors"
	"regexp"
	"strings"
)

var acmeChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_=-]{1,64}$`)

// EnsureAcmeChallengeFormat takes a domain name as a string, tests if it
// already has the acme-challenge format, and appends any missing substrings
// to ensure the acme challenge format.
func EnsureAcmeChallengeFormat(d string) (string, error) {
	if !strings.HasSuffix(d, ".") {
		d = d + "."
	}

	if !strings.HasPrefix(d, "_acme-challenge.") {
		d = "_acme-challenge." + d
	}

	return d, nil
}

// ValidateAcmeChallengeInput checks if the ACME challenge provided conforms to the
// ACME challenge format.
func ValidateAcmeChallengeInput(challenge string) error {
	if challenge == "" {
		return errors.New("Please provide \"challenge\"")
	}
	if acmeChallengeRe.MatchString(challenge) {
		return nil
	}
	return errors.New("ACME challenge provided has invalid format or is too long")
}
