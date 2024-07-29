package gssapi

import (
	"errors"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

/*
#include <gssapi.h>
*/
import "C"

type CallingError struct {
	g.FatalStatus
	CallingErrorCode CallingErrorCode
}

// Errors specific to the C bindings
type CallingErrorCode uint32

const (
	inaccessibleRead CallingErrorCode = iota + 1
	inaccessibleWrite
	badStructure
)

var ErrInaccessibleRead = errors.New("a required input parameter could not be read")
var ErrInaccessibleWrite = errors.New("a required output parameter could not be written")
var ErrBadStructure = errors.New("a parameter was malformed")

func (s CallingError) Calling() error {
	switch s.CallingErrorCode {
	default:
		return g.ErrBadStatus
	case inaccessibleRead:
		return ErrInaccessibleRead
	case inaccessibleWrite:
		return ErrInaccessibleWrite
	case badStructure:
		return ErrBadStructure
	}
}

func (s CallingError) Unwrap() []error {
	ret := []error{}

	if s.CallingErrorCode != 0 {
		ret = append(ret, s.Calling())
	}

	ret = append(ret, s.FatalStatus.Unwrap()...)

	return ret
}

func (s CallingError) Error() string {
	var ret string

	if s.CallingErrorCode != 0 {
		ret = "C bindings errors: " + s.Calling().Error()
	}

	fatalErrs := s.FatalStatus.Error()
	if fatalErrs != "" {
		ret += ".  GSSAPI errors: " + fatalErrs
	}

	return ret
}

func makeStatus(major, minor C.OM_uint32) error {
	return makeMechStatus(major, minor, 0)
}

func makeMechStatus(major, minor C.OM_uint32, mech g.GssMech) error {
	if major == 0 {
		return nil
	}

	calling_error := (major & 0xFF000000) >> 24 // bad call by us to gssapi
	routine_error := (major & 0x00FF0000) >> 16 // the "Fatal" errors
	supplementary := major & 0xffff

	// all errors are at least informational
	info := g.InfoStatus{
		InformationCode: g.InformationCode(supplementary),
	}

	// minor codes are specific to the mech
	if minor != 0 {
		minorErrors := gssMinorErrors(minor, mech)
		if len(minorErrors) > 0 {
			info.MechErrors = minorErrors
		}
	}

	if routine_error == 0 {
		return info
	}

	// some are also fatal
	fatal := g.FatalStatus{
		FatalErrorCode: g.FatalErrorCode(routine_error),
		InfoStatus:     info,
	}

	if calling_error == 0 {
		return fatal
	}

	// and then some are calling errors also, in the C bindings at least
	return CallingError{
		CallingErrorCode: CallingErrorCode(calling_error),
		FatalStatus:      fatal,
	}
}
