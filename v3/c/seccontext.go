package gssapi

/*
#include <gssapi.h>
gss_OID_desc GoStringToGssOID(_GoString_ s);

OM_uint32 init_sec_context (OM_uint32 *minor, const gss_cred_id_t cred_handle, gss_ctx_id_t *context_handle,
			const gss_name_t name, _GoString_ mechOid,	OM_uint32 reqFlags, OM_uint32 time_req, gss_buffer_t output_token) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);

	return gss_init_sec_context(minor, cred_handle, context_handle, name, &oid, reqFlags, time_req, GSS_C_NO_CHANNEL_BINDINGS,
						GSS_C_NO_BUFFER, NULL, output_token, NULL, NULL);
}
*/
import "C"

import (
	"fmt"
	"time"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type SecContext struct {
	id C.gss_ctx_id_t
}

func (library) InitSecContext(cred g.Credential, name g.GssName, mech g.GssMech, reqFlags g.ContextFlag, lifetime time.Duration) (g.SecContext, []byte, error) {
	mechOid := mech.Oid()

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
	var cOutToken C.gss_buffer_desc
	major := C.init_sec_context(&minor, cGssCred, &cGssCtxId, cGssName, string(mechOid), C.OM_uint32(reqFlags), C.OM_uint32(lifetime.Seconds()), &cOutToken)

	if major != 0 {
		return nil, nil, makeStatus(major, minor)
	}

	defer C.gss_release_buffer(&minor, &cOutToken)

	outToken := C.GoBytes(cOutToken.value, C.int(cOutToken.length))

	return &SecContext{
		id: cGssCtxId,
	}, outToken, nil
}

func (library) AcceptSecContext(cred g.Credential, inputToken []byte) (g.SecContext, *g.SecContextInfo, error) {
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
	var cOutToken C.gss_buffer_desc
	major := C.accept_sec_context(&minor, cGssCred, C.GSS_C_NO_CONTEXT, nil, nil, 

	if major != 0 {
		return nil, nil, makeStatus(major, minor)
	}

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
