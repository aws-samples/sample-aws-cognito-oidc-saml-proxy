package domain

import (
	"errors"
	"fmt"
)

// Fault classifies whether an error is the caller's problem (Client) or ours (Server).
type Fault int

const (
	FaultClient Fault = iota // 4xx — caller should fix the request
	FaultServer              // 5xx — our problem, may be retryable
)

// Error is a domain error with machine-readable code and fault classification.
type Error struct {
	Code    string // Machine-readable: "NotFound", "ValidationError", "Forbidden"
	Message string // Human-readable description
	Fault   Fault
	Err     error // Wrapped cause (optional)
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target matches this error's Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Predefined domain errors.
var (
	ErrNotFound       = &Error{Code: "NotFound", Message: "resource not found", Fault: FaultClient}
	ErrTenantRequired = &Error{Code: "TenantRequired", Message: "tenant context required", Fault: FaultClient}
	ErrInvalidConfig  = &Error{Code: "InvalidConfig", Message: "invalid configuration", Fault: FaultClient}
	ErrForbidden      = &Error{Code: "Forbidden", Message: "access denied", Fault: FaultClient}
	ErrConflict       = &Error{Code: "Conflict", Message: "resource already exists", Fault: FaultClient}
	ErrInternal       = &Error{Code: "InternalError", Message: "internal error", Fault: FaultServer}
)

// NewError creates a domain error wrapping a cause.
func NewError(base *Error, cause error) *Error {
	return &Error{
		Code:    base.Code,
		Message: base.Message,
		Fault:   base.Fault,
		Err:     cause,
	}
}

// Wrap creates a domain error with a custom message wrapping a cause.
func Wrap(code string, fault Fault, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Fault: fault, Err: cause}
}

// HTTPStatus returns the appropriate HTTP status code for a domain error.
func HTTPStatus(err error) int {
	var domErr *Error
	if errors.As(err, &domErr) {
		switch domErr.Code {
		case "NotFound":
			return 404
		case "Forbidden":
			return 403
		case "TenantRequired":
			return 403
		case "InvalidConfig", "ValidationError":
			return 400
		case "Conflict":
			return 409
		}
		if domErr.Fault == FaultServer {
			return 500
		}
		return 400
	}
	return 500
}

// ValidationError is an alias for backward compatibility.
// Use Error with Code "ValidationError" for new code.
type ValidationError = Error
