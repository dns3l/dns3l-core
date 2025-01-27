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
	Msg    string
	SubErr error
}

func (e *InvalidInputError) Error() string {
	if e.SubErr != nil {
		return e.SubErr.Error()
	}
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

type AlreadyExistsError struct {
	RequestedResource string
}

func (e *AlreadyExistsError) Error() string {
	if e.RequestedResource == "" {
		return "requested resource already exists"
	}

	return fmt.Sprintf("requested resource '%s' already exists", e.RequestedResource)

}

type Warning struct {
	SubErr error
}

func (e *Warning) Error() string {
	return e.SubErr.Error()

}
