package gssapi

/*
#include <gssapi.h>

gss_OID_desc GoStringToGssOID(_GoString_ s) {
	size_t l = _GoStringLen(s);
	void *elms = (void*)_GoStringPtr(s);
	gss_OID_desc oid = {l, elms};
	return oid;
}

gss_buffer_desc GoStringToGssBuffer(_GoString_ s) {
	size_t l = _GoStringLen(s);
	void *value = (void*)_GoStringPtr(s);
	gss_buffer_desc buf = {l, value};
	return buf;
}

// _GoString_ is really a convenient []byte here..
OM_uint32 import_name(_GoString_ name, _GoString_ nameOid, OM_uint32 *minor, gss_name_t *output_name) {
	gss_buffer_desc nameBuf = GoStringToGssBuffer(name);
	gss_OID_desc oid = GoStringToGssOID(nameOid);
	gss_OID pOid = oid.length > 0 ? &oid : GSS_C_NO_OID;

	return gss_import_name(minor, &nameBuf, pOid, output_name);
}

OM_uint32 canonicalize_name(const gss_name_t name, _GoString_ mechOid, OM_uint32 *minor, gss_name_t *output_name) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);

	return gss_canonicalize_name(minor, name, &oid, output_name);
}

OM_uint32 display_status(OM_uint32 status, int status_type, _GoString_ mechOid, OM_uint32 *minor, OM_uint32 *msgCtx, gss_buffer_desc *status_string) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);
	return gss_display_status(minor, status, status_type, &oid, msgCtx, status_string);
}

*/
// #cgo LDFLAGS: -lgssapi_krb5
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type GssName struct {
	name C.gss_name_t
}

func (_ library) ImportName(name string, nameType g.GssNameType) (g.GssName, error) {
	nameOid := nameType.Oid()
	var minor C.OM_uint32
	var gssName C.gss_name_t
	major := C.import_name(name, string(nameOid), &minor, &gssName)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name: gssName,
	}, nil
}

func (n *GssName) Compare(other g.GssName) (bool, error) {
	// other must be our type, not one from a different GSSAPI impl
	// .. but this method needs to implement gsscommon.GssName.Compare()
	otherName, ok := other.(*GssName)
	if !ok {
		return false, fmt.Errorf("can't compare %T with %T: %w", n, other, g.ErrBadName)
	}

	var minor C.OM_uint32
	var equal C.int
	major := C.gss_compare_name(&minor, n.name, otherName.name, &equal)
	if major != 0 {
		return false, makeStatus(major, minor)
	}

	t := false
	if equal != 0 {
		t = true
	}
	return t, nil
}

func (n *GssName) Display() (string, g.GssNameType, error) {
	var minor C.OM_uint32
	var outputBuf C.gss_buffer_desc
	var outType C.gss_OID // not to be freed..
	major := C.gss_display_name(&minor, n.name, &outputBuf, &outType)
	if major != 0 {
		return "", g.GSS_NO_OID, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &outputBuf)

	name := C.GoBytes(outputBuf.value, C.int(outputBuf.length))

	oid := C.GoBytes(outType.elements, C.int(outType.length))
	nameType, err := g.NameFromOid(oid)
	if err != nil {
		return "", g.GSS_NO_OID, makeStatus(major, minor)
	}

	return string(name), nameType, nil
}

func (n *GssName) Release() error {
	if n.name == nil {
		return nil
	}
	var minor C.OM_uint32
	major := C.gss_release_name(&minor, &n.name)
	n.name = nil
	return makeStatus(major, minor)
}

func (n *GssName) InquireMechs() ([]g.GssMech, error) {
	var minor C.OM_uint32
	var cMechSet C.gss_OID_set
	major := C.gss_inquire_mechs_for_name(&minor, n.name, &cMechSet)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	defer C.gss_release_oid_set(&minor, &cMechSet)

	// make a Go slice backed by the C array..
	var oidArray *C.gss_OID_desc = cMechSet.elements
	mechSlice := unsafe.Slice(oidArray, cMechSet.count)

	ret := make([]g.GssMech, 0, len(mechSlice))
	for _, cOid := range mechSlice {
		goMechOid := C.GoBytes(cOid.elements, C.int(cOid.length))

		mech, err := g.MechFromOid(goMechOid)
		switch {
		default:
			ret = append(ret, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, err
		}
	}

	return ret, nil
}

func (n *GssName) Canonicalize(mech g.GssMech) (g.GssName, error) {
	mechOid := mech.Oid()
	var minor C.OM_uint32
	var outName C.gss_name_t
	major := C.canonicalize_name(n.name, string(mechOid), &minor, &outName)
	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	return &GssName{
		name: outName,
	}, nil
}

func (n *GssName) Export() ([]byte, error) {
	var minor C.OM_uint32
	var outputBuf C.gss_buffer_desc
	major := C.gss_export_name(&minor, n.name, &outputBuf)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &outputBuf)

	exported := C.GoBytes(outputBuf.value, C.int(outputBuf.length))

	return exported, nil
}

func (n *GssName) Duplicate() (g.GssName, error) {
	var minor C.OM_uint32
	var name C.gss_name_t
	major := C.gss_duplicate_name(&minor, n.name, &name)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name: name,
	}, nil
}

// Ask GSSAPI for the error string associated a the minor (mech specific)
// error code
func gssMinorErrors(minor C.OM_uint32, mech g.GssMech) []error {
	mechOid := mech.Oid()
	var lMinor, msgCtx C.OM_uint32
	var statusString C.gss_buffer_desc

	ret := []error{}

	for {
		major := C.display_status(minor, 2, string(mechOid), &lMinor, &msgCtx, &statusString)
		if major != 0 {
			ret = append(ret, fmt.Errorf("got GSS major code %d while finding string for minor code %d", major, minor))
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
