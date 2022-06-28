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
	} else {
		return fmt.Sprintf("Requested resource '%s' not found", e.RequestedResource)
	}

}
