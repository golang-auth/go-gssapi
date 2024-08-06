package gssapi

/*
#include <gssapi.h>
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type SecContext struct {
	id             C.gss_ctx_id_t
	continueNeeded bool
}

func oid2Coid(oid g.Oid) C.gss_OID_desc {
	return C.gss_OID_desc{
		length:   C.OM_uint32(len(oid)),
		elements: unsafe.Pointer(&oid[0]),
	}
}
func (library) InitSecContextOld(name g.GssName, cred g.Credential, mech g.GssMech, reqFlags g.ContextFlag, lifetime time.Duration) (g.SecContext, []byte, error) {
	cMechOid := oid2Coid(mech.Oid())

	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if cred != nil {
		lCred, ok := cred.(*Credential)
		if !ok {
			return nil, nil, fmt.Errorf("bad credential type %T, %w", lCred, g.ErrDefectiveCredential)
		}

		cGssCred = lCred.id
	}

	var cGssName C.gss_name_t
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return nil, nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cGssCtxId C.gss_ctx_id_t
	var cOutToken C.gss_buffer_desc // cOutToken.value allocated by GSSAPI; released by *1
	major := C.gss_init_sec_context(&minor, cGssCred, &cGssCtxId, cGssName, &cMechOid, C.OM_uint32(reqFlags), C.OM_uint32(lifetime.Seconds()), nil, nil, nil, &cOutToken, nil, nil)

	if major != 0 && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return &SecContext{
		id:             cGssCtxId,
		continueNeeded: major == C.GSS_S_CONTINUE_NEEDED,
	}, outToken, nil
}

func (library) InitSecContext(name g.GssName, opts ...g.InitSecContextOption) (g.SecContext, []byte, error) {
	o := g.InitSecContextOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	cMechOid := oid2Coid(o.Mech.Oid())

	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if o.Credential != nil {
		lCred, ok := o.Credential.(*Credential)
		if !ok {
			return nil, nil, fmt.Errorf("bad credential type %T, %w", lCred, g.ErrDefectiveCredential)
		}

		cGssCred = lCred.id
	}

	var cGssName C.gss_name_t
	if name != nil {
		lName, ok := name.(*GssName)
		if !ok {
			return nil, nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = lName.name
	}

	var minor C.OM_uint32
	var cGssCtxId C.gss_ctx_id_t
	var cOutToken C.gss_buffer_desc // cOutToken.value allocated by GSSAPI; released by *1
	major := C.gss_init_sec_context(&minor, cGssCred, &cGssCtxId, cGssName, &cMechOid, C.OM_uint32(o.Flags), C.OM_uint32(o.Lifetime.Seconds()), nil, nil, nil, &cOutToken, nil, nil)

	if major != 0 && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return &SecContext{
		id:             cGssCtxId,
		continueNeeded: major == C.GSS_S_CONTINUE_NEEDED,
	}, outToken, nil
}

func (library) AcceptSecContext(cred g.Credential, inputToken []byte) (g.SecContext, []byte, error) {
	// get the C cred ID and name
	var cGssCred C.gss_cred_id_t = C.GSS_C_NO_CREDENTIAL
	if cred != nil {
		lCred, ok := cred.(*Credential)
		if !ok {
			return nil, nil, fmt.Errorf("bad credential type %T, %w", lCred, g.ErrDefectiveCredential)
		}

		cGssCred = lCred.id
	}

	var minor C.OM_uint32
	var cGssCtxId C.gss_ctx_id_t
	var cOutToken C.gss_buffer_desc // cOutToken.value allocated by GSSAPI; released by *1
	cInputToken, pinner := bytesToCBuffer(inputToken)
	defer pinner.Unpin()

	major := C.gss_accept_sec_context(&minor, &cGssCtxId, cGssCred, &cInputToken, nil, nil, nil, &cOutToken, nil, nil, nil)

	if major != 0 && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated buffer
	defer C.gss_release_buffer(&minor, &cOutToken)

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))
	return &SecContext{
		id:             cGssCtxId,
		continueNeeded: major == C.GSS_S_CONTINUE_NEEDED,
	}, outToken, nil
}

func (c *SecContext) ContinueNeeded() bool {
	return c.continueNeeded
}

func (c *SecContext) Delete() ([]byte, error) {
	if c.id == nil {
		return nil, nil
	}
	var minor C.OM_uint32
	var cOutToken C.gss_buffer_desc
	major := C.gss_delete_sec_context(&minor, &c.id, &cOutToken)
	defer C.gss_release_buffer(&minor, &cOutToken)

	c.id = nil
	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return outToken, makeStatus(major, minor)
}

func (c *SecContext) Inquire() (*g.SecContextInfo, error) {
	var minor C.OM_uint32
	var cSrcName, cTargName C.gss_name_t // allocated by GSSAPI;  released by *1
	var cLifetime, cFlags C.OM_uint32
	var cMechOid C.gss_OID // do not free
	var cLocallyInitiated, cOpen C.int
	major := C.gss_inquire_context(&minor, c.id, &cSrcName, &cTargName, &cLifetime, &cMechOid, &cFlags, &cLocallyInitiated, &cOpen)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	var srcNameStr, targNameStr string
	var srcNameType, targNameType g.GssNameType
	var err error

	if cSrcName != nil {
		srcName := nameFromGssInternal(cSrcName)
		defer srcName.Release() // *1 release GSSAPI allocated name
		srcNameStr, srcNameType, err = srcName.Display()
		if err != nil {
			return nil, err
		}
	}

	if cTargName != nil {
		targName := nameFromGssInternal(cTargName)
		defer targName.Release() // *1 release GSSAPI allocated name
		targNameStr, targNameType, err = targName.Display()
		if err != nil {
			return nil, err
		}
	}

	mech, err := g.MechFromOid(oidFromGssOid(cMechOid))
	if err != nil {
		return nil, err
	}

	// treat protection and transferrable flags separately -- they are not
	// request flags and are unknown to the interface
	protFlag := cFlags & C.GSS_C_PROT_READY_FLAG
	transFlag := cFlags & C.GSS_C_TRANS_FLAG

	cFlags &= ^C.OM_uint32(C.GSS_C_PROT_READY_FLAG | C.GSS_C_TRANS_FLAG)

	var expTime time.Time
	if cLifetime > 0 {
		expTime = time.Now().Add(time.Duration(cLifetime) * time.Second)
	}

	return &g.SecContextInfo{
		InitiatorName:     srcNameStr,
		InitiatorNameType: srcNameType,
		AcceptorName:      targNameStr,
		AcceptorNameType:  targNameType,
		Mech:              mech,
		Flags:             g.ContextFlag(cFlags),
		ExpiresAt:         expTime,
		LocallyInitiated:  cLocallyInitiated != 0,
		FullyEstablished:  cOpen != 0,
		ProtectionReady:   protFlag > 0,
		Transferrable:     transFlag > 0,
	}, nil
}
