package gsscommon

import (
	"errors"
	"strings"
)

type InfoStatus struct {
	InformationCode InformationCode
	MechErrors      []error
}

type FatalStatus struct {
	InfoStatus
	FatalErrorCode FatalErrorCode
}

// Values of runtime error and info codes are the same as the C bindings for compatibility
// See RFC 2744 § 3.9.1
type FatalErrorCode uint32
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
	errContexctExpired
	errFailure
	errBadQop
	errUnauthorized
	errUnavailable
	errDuplicateElement
	errNameNotMn

	errBadSig = errBadMic
)

const (
	infoContinueNeeded InformationCode = 1 << iota
	infoDuplicateToken
	infoOldToken
	infoUnseqToken
	infoGapToken
)

var ErrBadMech = errors.New("an unsupported mechanism was requested")
var ErrBadName = errors.New("an invalid name was supplied")
var ErrBadNameType = errors.New("a supplied name was of an unsupported type")
var ErrBadBindings = errors.New("incorrect channel bindings were supplied")
var ErrBadStatus = errors.New("an invalid status code was supplied")
var ErrBadMic = errors.New("a token had an invalid signature")
var ErrBadSig = ErrBadMic
var ErrNoCred = errors.New("no credentials were supplied, or the credentials were unavailable or inaccessible")
var ErrNoContext = errors.New("no context has been established")
var ErrDefectiveToken = errors.New("nvalid token was supplied")
var ErrDefectiveCredential = errors.New("invalid credential was supplied")
var ErrCredentialsExpired = errors.New("the referenced credentials have expired")
var ErrContextExpired = errors.New("the context has expired")
var ErrFailure = errors.New("unspecified GSS failure.  Minor code may provide more information")
var ErrBadQop = errors.New("the quality-of-protection (QOP) requested could not be provided")
var ErrUnauthorized = errors.New("the operation is forbidden by local security policy")
var ErrUnavailable = errors.New("the operation or option is not available or supported")
var ErrDuplicateElement = errors.New("the requested credential element already exists")
var ErrNameNotMn = errors.New("the provided name was not mechsnism specific (MN)")

//lint:ignore ST1012 these aren't actually errors
var InfoContinueNeeded = errors.New("the routine must be called again to complete its function")

//lint:ignore ST1012 these aren't actually errors
var InfoDuplicateToken = errors.New(`the token was a duplicate of an earlier token`)

//lint:ignore ST1012 these aren't actually errors
var InfoOldToken = errors.New("the token's validity period has expired")

//lint:ignore ST1012 these aren't actually errors
var InfoUnseqToken = errors.New("a later token has already been processed")

//lint:ignore ST1012 these aren't actually errors
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
	case errContexctExpired:
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
