// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"strings"
)

// InfoStatus represents informational status codes returned when an informational code is available
// but a function otherwise succeeded. This is only the case for the message-related methods of
// SecContext, such as SecContext.VerifyMIC and SecContext.Unwrap.
//
// The Go bindings use Go's standard error interface instead of the major and minor status codes
// specified in RFC 2743 § 1.2.1. InfoStatus objects are returned when an informational code
// is available but a function otherwise succeeded.
type InfoStatus struct {
	InformationCode InformationCode // The informational status code
	MechErrors      []error         // Mechanism-specific errors
}

// FatalStatus represents fatal error status codes returned when a function fails.
// Fatal errors may also include an embedded InfoStatus error.
//
// The Go bindings use Go's standard error interface instead of the major and minor status codes
// specified in RFC 2743 § 1.2.1. FatalStatus objects are returned when a function fails.
type FatalStatus struct {
	InfoStatus                    // Embedded informational status
	FatalErrorCode FatalErrorCode // The fatal error code
}

// FatalErrorCode represents fatal error codes. Values of runtime error codes are the same as
// the C bindings for compatibility. See RFC 2744 § 3.9.1.
type FatalErrorCode uint32

// InformationCode represents informational status codes. Values of runtime info codes are the same as
// the C bindings for compatibility. See RFC 2744 § 3.9.1.
type InformationCode uint32

const (
	complete FatalErrorCode = iota
	errBadMech
	errBadName
	errBadNameType
	errBadBindings
	errBadStatus
	errBadMic
	errNoCred
	errNoContext
	errDefectiveToken
	errDefectiveCredential
	errCredentialsExpired
	errContextExpired
	errFailure
	errBadQop
	errUnauthorized
	errUnavailable
	errDuplicateElement
	errNameNotMn
	errBadMechAttr

	errBadSig = errBadMic
)

const (
	infoContinueNeeded InformationCode = 1 << iota
	infoDuplicateToken
	infoOldToken
	infoUnseqToken
	infoGapToken
)

// Fatal error variables that correspond to the fatal error codes defined by RFC 2743.
// These variables implement the error interface and can be used with Go's standard error handling.

var ErrBadMech = errors.New("an unsupported mechanism was requested")
var ErrBadName = errors.New("an invalid name was supplied")
var ErrBadNameType = errors.New("a supplied name was of an unsupported type")
var ErrBadBindings = errors.New("incorrect channel bindings were supplied")
var ErrBadStatus = errors.New("an invalid status code was supplied")
var ErrBadMic = errors.New("a token had an invalid signature")
var ErrBadSig = ErrBadMic // ErrBadSig is an alias for ErrBadMic for compatibility
var ErrNoCred = errors.New("no credentials were supplied, or the credentials were unavailable or inaccessible")
var ErrNoContext = errors.New("no context has been established")
var ErrDefectiveToken = errors.New("invalid token was supplied")
var ErrDefectiveCredential = errors.New("invalid credential was supplied")
var ErrCredentialsExpired = errors.New("the referenced credentials have expired")
var ErrContextExpired = errors.New("the context has expired")
var ErrFailure = errors.New("unspecified GSS failure.  Minor code may provide more information")
var ErrBadQop = errors.New("the quality-of-protection (QOP) requested could not be provided")
var ErrUnauthorized = errors.New("the operation is forbidden by local security policy")
var ErrUnavailable = errors.New("the operation or option is not available or supported")
var ErrDuplicateElement = errors.New("the requested credential element already exists")
var ErrNameNotMn = errors.New("the provided name was not mechanism specific (MN)")
var ErrBadMechAttr = errors.New("an unsupported mechanism attribute was requested")

// Informational status variables that correspond to the informational codes defined by RFC 2743.
// These are returned by InfoStatus.Unwrap() and FatalStatus.Unwrap() and can be used with Go's
// standard error handling mechanisms like errors.Is().

//nolint:staticcheck // ST1012 these aren't actually errors
var InfoContinueNeeded = errors.New("the routine must be called again to complete its function")

//nolint:staticcheck // ST1012 these aren't actually errors
var InfoDuplicateToken = errors.New(`the token was a duplicate of an earlier token`)

//nolint:staticcheck // ST1012 these aren't actually errors
var InfoOldToken = errors.New("the token's validity period has expired")

//nolint:staticcheck // ST1012 these aren't actually errors
var InfoUnseqToken = errors.New("a later token has already been processed")

//nolint:staticcheck // ST1012 these aren't actually errors
var InfoGapToken = errors.New("an expected per-message token was not received")

func (s FatalStatus) Fatal() error {
	switch s.FatalErrorCode {
	default:
		return ErrBadStatus
	case errBadMech:
		return ErrBadMech
	case errBadName:
		return ErrBadName
	case errBadNameType:
		return ErrBadNameType
	case errBadBindings:
		return ErrBadBindings
	case errBadStatus:
		return ErrBadStatus
	case errBadMic:
		return ErrBadMic
	case errNoCred:
		return ErrNoCred
	case errNoContext:
		return ErrNoContext
	case errDefectiveToken:
		return ErrDefectiveToken
	case errDefectiveCredential:
		return ErrDefectiveCredential
	case errCredentialsExpired:
		return ErrCredentialsExpired
	case errContextExpired:
		return ErrContextExpired
	case errFailure:
		return ErrFailure
	case errBadQop:
		return ErrBadQop
	case errUnauthorized:
		return ErrUnauthorized
	case errUnavailable:
		return ErrUnavailable
	case errDuplicateElement:
		return ErrDuplicateElement
	case errNameNotMn:
		return ErrNameNotMn
	case errBadMechAttr:
		return ErrBadMechAttr
	}
}

func (s InfoStatus) Unwrap() []error {
	ret := []error{}

	if s.InformationCode&infoContinueNeeded > 0 {
		ret = append(ret, InfoContinueNeeded)
	}
	if s.InformationCode&infoDuplicateToken > 0 {
		ret = append(ret, InfoDuplicateToken)
	}
	if s.InformationCode&infoOldToken > 0 {
		ret = append(ret, InfoOldToken)
	}
	if s.InformationCode&infoUnseqToken > 0 {
		ret = append(ret, InfoUnseqToken)
	}
	if s.InformationCode&infoGapToken > 0 {
		ret = append(ret, InfoGapToken)
	}

	return ret
}

func (s InfoStatus) Error() string {
	var ret string

	infoErrs := s.Unwrap()
	infoStrings := make([]string, len(infoErrs))
	for i, err := range infoErrs {
		infoStrings[i] = err.Error()
	}

	ret += strings.Join(infoStrings, "; ")

	return ret
}

func (s FatalStatus) Unwrap() []error {
	ret := []error{}

	if s.FatalErrorCode != complete {
		ret = append(ret, s.Fatal())
	}

	ret = append(ret, s.InfoStatus.Unwrap()...)

	return ret
}

func (s FatalStatus) Error() string {
	var parts []string

	if s.FatalErrorCode != complete {
		fatal := s.Fatal()
		// only include the spiel about maybe the minor code being helpful if we do
		// actually have a mech error (from the minor code)
		if !(fatal == ErrFailure && len(s.MechErrors) > 0) {
			parts = append(parts, fatal.Error())
		}
	}

	if s.MechErrors != nil {
		mechStrs := make([]string, len(s.MechErrors))
		for i, e := range s.MechErrors {
			mechStrs[i] = e.Error()
		}
		parts = append(parts, strings.Join(mechStrs, "; "))
	}

	infoErrs := s.InfoStatus.Error()
	if infoErrs != "" {
		parts = append(parts, "Additionally: "+infoErrs)
	}

	return strings.Join(parts, ".  ")
}
