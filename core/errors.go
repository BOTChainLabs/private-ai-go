package core

import (
	"context"
	"errors"
	"fmt"
)

// Error codes returned by the SDK. They are stable: callers may branch on them.
const (
	CodeInvalidRequest      = "INVALID_REQUEST"
	CodeModelNotAllowed     = "MODEL_NOT_ALLOWED"
	CodeAttestationFailed   = "ATTESTATION_FAILED"
	CodeTLSPinMismatch      = "TLS_PIN_MISMATCH"
	CodeReceiptInvalid      = "RECEIPT_INVALID"
	CodeRouteNotTEE         = "ROUTE_NOT_TEE"
	CodeEvidenceUnavailable = "EVIDENCE_UNAVAILABLE"
	CodeVerifierUnavailable = "VERIFIER_UNAVAILABLE"
	CodeProviderError       = "PROVIDER_ERROR"
)

// Error carries a stable code and, when a request reached the provider, the
// verification details that explain the failure.
type Error struct {
	Code         string
	Message      string
	Verification *Verification
	Cause        error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("privateai: %s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("privateai: %s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

func Errorf(code string, cause error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Cause: cause}
}

// Wrap gives err an SDK code. When the caller's own context has ended, err
// is returned unchanged: cancellation is the caller's decision, not a
// provider failure. The SDK's internal timeouts are wrapped like any other
// failure.
func Wrap(callerCtx context.Context, code string, err error, msg string) error {
	if callerCtx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	return &Error{Code: code, Message: msg, Cause: err}
}

// StreamUnfinished is the error for verifying a stream that was not read to
// the end, or that failed while reading (cause).
func StreamUnfinished(p ProviderID, model, route string, cause error) *Error {
	reason := "stream was not read to the end"
	if cause != nil {
		reason = "stream failed: " + cause.Error()
	}
	v := Verification{Status: Unverified, Provider: p, Model: model, Route: route, Reasons: []string{reason}}
	return &Error{Code: CodeEvidenceUnavailable, Message: reason, Verification: &v, Cause: cause}
}
