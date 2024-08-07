package gssapi

import (
	"errors"
	"fmt"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

/*
#include <gssapi.h>

gss_OID_desc GoStringToGssOID(_GoString_ s);

OM_uint32 display_status(OM_uint32 status, int status_type, _GoString_ mechOid, OM_uint32 *minor, OM_uint32 *msgCtx, gss_buffer_desc *status_string) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);
	return gss_display_status(minor, status, status_type, &oid, msgCtx, status_string);
}
*/
import "C"

type FatalCallingError struct {
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

func (s FatalCallingError) Calling() error {
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

func (s FatalCallingError) Unwrap() []error {
	ret := []error{}

	if s.CallingErrorCode != 0 {
		ret = append(ret, s.Calling())
	}

	ret = append(ret, s.FatalStatus.Unwrap()...)

	return ret
}

func (s FatalCallingError) Error() string {
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

	// see RFC 2744 § 3.9.1
	calling_error := (major & 0xFF000000) >> 24 // bad call by us to gssapi
	routine_error := (major & 0x00FF0000) >> 16 // the "Fatal" errors
	supplementary := major & 0xffff

	// all errors are at least informational
	info := g.InfoStatus{
		InformationCode: g.InformationCode(supplementary),
	}

	// minor codes are specific to the mech; there are no standard codes
	// so we just deposit error objects with description strings from
	// the C API
	if minor != 0 {
		minorErrors := gssMinorErrors(minor, mech)
		if len(minorErrors) > 0 {
			info.MechErrors = minorErrors
		}
	}

	if routine_error == 0 && calling_error == 0 {
		if calling_error == 0 {
			return info
		}
	}

	// some are also fatal (always if there is a calling error)
	fatal := g.FatalStatus{
		FatalErrorCode: g.FatalErrorCode(routine_error),
		InfoStatus:     info,
	}

	if calling_error == 0 {
		return fatal
	}

	// and then some are calling errors also, in the C bindings at least
	return FatalCallingError{
		CallingErrorCode: CallingErrorCode(calling_error),
		FatalStatus:      fatal,
	}
}

// Ask GSSAPI for the error strings associated a the minor (mech specific)
// error code
func gssMinorErrors(minor C.OM_uint32, mech g.GssMech) []error {
	mechOid := mech.Oid()
	var lMinor, msgCtx C.OM_uint32
	var statusString C.gss_buffer_desc

	ret := []error{}

	for {
		major := C.display_status(minor, 2, string(mechOid), &lMinor, &msgCtx, &statusString)
		if major != 0 {
			// specifically do not call makeStatus here - we might end up in a loop..
			ret = append(ret, fmt.Errorf("got GSS error %d/%d while finding string for minor code %d", major, lMinor, minor))
			break
		}

		defer C.gss_release_buffer(&lMinor, &statusString)

		s := C.GoStringN((*C.char)(statusString.value), C.int(statusString.length))
		ret = append(ret, errors.New(s))

		// all done when the message context is set to zero by gss_display_status
		if msgCtx == 0 {
			break
		}
	}

	return ret
}
