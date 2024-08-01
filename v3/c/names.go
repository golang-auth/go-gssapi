package gssapi

/*
#include <gssapi.h>

gss_OID_desc GoStringToGssOID(_GoString_ s);
gss_buffer_desc GoStringToGssBuffer(_GoString_ s);

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


*/
// #cgo LDFLAGS: -lgssapi_krb5
import "C"

import (
	"errors"
	"fmt"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type GssName struct {
	name C.gss_name_t
}

func nameFromGssInternal(name C.gss_name_t) GssName {
	return GssName{name}
}

func (library) ImportName(name string, nameType g.GssNameType) (g.GssName, error) {
	nameOid := nameType.Oid()
	var minor C.OM_uint32
	var cGssName C.gss_name_t
	major := C.import_name(name, string(nameOid), &minor, &cGssName)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name: cGssName,
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
	var cEqual C.int
	major := C.gss_compare_name(&minor, n.name, otherName.name, &cEqual)
	if major != 0 {
		return false, makeStatus(major, minor)
	}

	t := false
	if cEqual != 0 {
		t = true
	}
	return t, nil
}

func (n *GssName) Display() (string, g.GssNameType, error) {
	var minor C.OM_uint32
	var cOutputBuf C.gss_buffer_desc // outputBuf.value allocated by GSSAPI; released by *1
	var cOutType C.gss_OID           // not to be freed (static GSSAPI data)
	major := C.gss_display_name(&minor, n.name, &cOutputBuf, &cOutType)
	if major != 0 {
		return "", g.GSS_NO_OID, makeStatus(major, minor)
	}

	// *1 release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutputBuf)

	name := C.GoBytes(cOutputBuf.value, C.int(cOutputBuf.length))

	oid := C.GoBytes(cOutType.elements, C.int(cOutType.length))
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
	var cMechSet C.gss_OID_set // cMechSet.elements allocated by GSSAPI; released by *1
	major := C.gss_inquire_mechs_for_name(&minor, n.name, &cMechSet)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	// *1   release GSSAPI allocated array
	defer C.gss_release_oid_set(&minor, &cMechSet)

	ret := make([]g.GssMech, 0, cMechSet.count)
	mechOids := oidsFromGssOidSet(cMechSet)

	for _, oid := range mechOids {
		mech, err := g.MechFromOid(oid)
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
	var cOutName C.gss_name_t
	major := C.canonicalize_name(n.name, string(mechOid), &minor, &cOutName)
	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	return &GssName{
		name: cOutName,
	}, nil
}

func (n *GssName) Export() ([]byte, error) {
	var minor C.OM_uint32
	var cOutputBuf C.gss_buffer_desc // cOutputBuf.value allocated by GSSAPI; released by *1
	major := C.gss_export_name(&minor, n.name, &cOutputBuf)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutputBuf)

	exported := C.GoBytes(cOutputBuf.value, C.int(cOutputBuf.length))

	return exported, nil
}

func (n *GssName) Duplicate() (g.GssName, error) {
	var minor C.OM_uint32
	var cOutName C.gss_name_t
	major := C.gss_duplicate_name(&minor, n.name, &cOutName)
	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	return &GssName{
		name: cOutName,
	}, nil
}
