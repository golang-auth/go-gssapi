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

*/
import "C"

import (
	"runtime"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

func oidsFromGssOidSet(oidSet C.gss_OID_set) []g.Oid {
	ret := make([]g.Oid, oidSet.count)

	var oidArray *C.gss_OID_desc = oidSet.elements
	oidSlice := unsafe.Slice(oidArray, oidSet.count)
	for i, cOid := range oidSlice {
		ret[i] = C.GoBytes(cOid.elements, C.int(cOid.length))
	}

	return ret
}

func oidFromGssOid(cOid C.gss_OID) g.Oid {
	return C.GoBytes(cOid.elements, C.int(cOid.length))
}

func gssOidSetFromOids(oids []g.Oid) gssOidSet {
	ret := gssOidSet{}

	if len(oids) > 0 {
		ret.oidPtrs = make([]C.gss_OID, len(oids))

		for i, oid := range oids {
			cOid := C.gss_OID_desc{C.uint(len(oid)), unsafe.Pointer(&oid[0])}
			ret.oidPtrs[i] = &cOid
		}

		ret.oidSet = &C.gss_OID_set_desc{C.size_t(len(oids)), ret.oidPtrs[0]}
	}

	return ret
}

type gssOidSet struct {
	pinner  runtime.Pinner
	oidSet  C.gss_OID_set
	oidPtrs []C.gss_OID
}

func (oidset *gssOidSet) Pin() {
	for _, p := range oidset.oidPtrs {
		oidset.pinner.Pin(p)
	}
}

func (oidset *gssOidSet) Unpin() {
	oidset.pinner.Unpin()
}

func mechsToOids(mechs []g.GssMech) []g.Oid {
	ret := make([]g.Oid, len(mechs))
	for i, mech := range mechs {
		ret[i] = mech.Oid()
	}

	return ret
}

func bytesToCBuffer(b []byte) (C.gss_buffer_desc, runtime.Pinner) {
	pinner := runtime.Pinner{}

	value := unsafe.Pointer(nil)
	if len(b) > 0 {
		value = unsafe.Pointer(&b[0])
		pinner.Pin(&b[0])
	}
	ret := C.gss_buffer_desc{
		length: C.size_t(len(b)),
		value:  value,
	}

	return ret, pinner
}
