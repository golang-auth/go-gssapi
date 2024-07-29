package gssapi

/*
#include <gssapi.h>


*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type Credential struct {
	id        C.gss_cred_id_t
	expiresAt *time.Time
}

func (library) AcquireCredential(name g.GssName, lifetime time.Duration, mechs []g.GssMech, usage g.CredUsage) (g.Credential, error) {
	pin := runtime.Pinner{}
	defer pin.Unpin()

	// turn the mechs into an array of OIDs
	var cOidSet C.gss_OID_set
	if len(mechs) > 0 {
		var oidPtrs = make([]C.gss_OID, len(mechs))
		for i, m := range mechs {
			oidBytes := m.Oid()
			cOid := C.gss_OID_desc{C.uint(len(oidBytes)), unsafe.Pointer(&oidBytes[0])}
			oidPtrs[i] = &cOid

			// these pointers need pinning because they are not directly passed to C
			pin.Pin(&cOid)
		}
		cOidSet = &C.gss_OID_set_desc{C.size_t(len(oidPtrs)), oidPtrs[0]}
	}

	var gssName C.gss_name_t
	if name != nil {
		cName, ok := name.(*GssName)
		if !ok {
			return false, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		gssName = cName.name
	}

	var minor C.OM_uint32
	var credId C.gss_cred_id_t
	var actualMechs C.gss_OID_set
	var timeRec C.OM_uint32
	major := C.gss_acquire_cred(&minor, gssName, C.OM_uint32(lifetime.Seconds()), cOidSet, C.int(usage), &credId, &actualMechs, &timeRec)

	if major != 0 {
		//return nil, makeMechStatus(major, minor, mechs[0])
		return nil, makeStatus(major, minor)
	}

	C.gss_release_oid_set(&minor, &actualMechs)

	return &Credential{
		id: credId,
	}, nil
}
