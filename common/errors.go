package common

import "fmt"

// A NotFoundError is thrown if the requested resource was not found or is not supposed
// to exist at all
type NotFoundError struct {
	RequestedResource string
}

func (e *NotFoundError) Error() string {
	if e.RequestedResource == "" {
		return "requested resource not found"
	}

	return fmt.Sprintf("requested resource '%s' not found", e.RequestedResource)

}

type NotAuthnedError struct {
	Msg string
}

func (e *NotAuthnedError) Error() string {
	return e.Msg
}

type UnauthzedError struct {
	Msg string
}

func (e *UnauthzedError) Error() string {
	return e.Msg
}

type InvalidInputError struct {
	Msg string
}

func (e *InvalidInputError) Error() string {
	return e.Msg
}

type DisabledError struct {
	RequestedResource string
}

func (e *DisabledError) Error() string {
	if e.RequestedResource == "" {
		return "requested resource is disabled"
	}

	return fmt.Sprintf("requested resource '%s' is disabled", e.RequestedResource)

}
