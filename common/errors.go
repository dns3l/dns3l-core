package common

import "fmt"

//A NotFoundError is thrown if the requested resource was not found or is not supposed
//to exist at all
type NotFoundError struct {
	RequestedResource string
}

func (e *NotFoundError) Error() string {
	if e.RequestedResource == "" {
		return "Requested resource not found"
	}

	return fmt.Sprintf("Requested resource '%s' not found", e.RequestedResource)

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
