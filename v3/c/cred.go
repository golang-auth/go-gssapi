package gssapi

/*
#include <gssapi.h>
#include <stdio.h>

gss_OID_desc GoStringToGssOID(_GoString_ s);

OM_uint32 inquire_cred_by_mech (OM_uint32 *minor, const gss_cred_id_t cred_handle,  _GoString_ mechOid,
            gss_name_t *output_name, OM_uint32 *init_life, OM_uint32 *accept_life, gss_cred_usage_t *usage) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);

	return gss_inquire_cred_by_mech(minor, cred_handle, &oid, output_name, init_life, accept_life, usage);
}

OM_uint32 add_cred(OM_uint32 *minor, const gss_cred_id_t cred_handle, const gss_name_t name, _GoString_ mechOid,
			gss_cred_usage_t usage, OM_uint32 initiator_lifetime, OM_uint32 acceptor_lifetime,
			gss_OID_set *actual_mechs, OM_uint32 *initiator_rec, OM_uint32 *acceptor_rec) {
	gss_OID_desc oid = GoStringToGssOID(mechOid);

	return gss_add_cred(minor, cred_handle, name, &oid, usage, initiator_lifetime, acceptor_lifetime, NULL,
		    actual_mechs, initiator_rec, acceptor_rec );
}

*/
import "C"

import (
	"errors"
	"fmt"
	"time"

	g "github.com/golang-auth/go-gssapi/v3/interface"
)

type Credential struct {
	id C.gss_cred_id_t
}

func (library) AcquireCredential(name g.GssName, mechs []g.GssMech, usage g.CredUsage, lifetime time.Duration) (g.Credential, *g.CredInfo, error) {
	// turn the mechs into an array of OIDs
	gssOidSet := gssOidSetFromOids(mechsToOids(mechs))
	gssOidSet.Pin()
	defer gssOidSet.Unpin()

	var cGssName C.gss_name_t
	if name != nil {
		cName, ok := name.(*GssName)
		if !ok {
			return nil, nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = cName.name
	}

	var minor C.OM_uint32
	var cCredId C.gss_cred_id_t
	var cActualMechs C.gss_OID_set // cActualMechs.elements allocated by GSSAPI; released by *1
	var cTimeRec C.OM_uint32
	major := C.gss_acquire_cred(&minor, cGssName, C.OM_uint32(lifetime.Seconds()), gssOidSet.oidSet, C.int(usage), &cCredId, &cActualMechs, &cTimeRec)

	if major != 0 {
		return nil, nil, makeStatus(major, minor)
	}

	// *1  release GSSAPI allocated array
	defer C.gss_release_oid_set(&minor, &cActualMechs)

	cred := &Credential{
		id: cCredId,
	}
	info := &g.CredInfo{
		Usage: usage,
	}

	if name != nil {
		var err error
		info.Name, info.NameType, err = name.Display()
		if err != nil {
			return nil, nil, err
		}
	}

	// we might get a validity period back from GSSAPI, though we don't actually know whether that
	// is for the acceptor or the initiator if we asked for a credential for both
	if cTimeRec != C.GSS_C_INDEFINITE {
		t := time.Now().Add(time.Second * time.Duration(cTimeRec)).Round(time.Second)
		switch usage {
		default:
			info.AcceptorExpiry = &t
			info.InitiatorExpiry = &t
		case g.CredUsageAcceptOnly:
			info.AcceptorExpiry = &t
		case g.CredUsageInitiateOnly:
			info.InitiatorExpiry = &t
		}
	}

	actualMechOids := oidsFromGssOidSet(cActualMechs)
	for _, oid := range actualMechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			info.Mechs = append(info.Mechs, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, nil, err
		}

	}

	return cred, info, nil
}

func (c *Credential) Release() error {
	if c.id == nil {
		return nil
	}
	var minor C.OM_uint32
	major := C.gss_release_cred(&minor, &c.id)
	c.id = nil
	return makeStatus(major, minor)
}

func (c *Credential) Inquire() (*g.CredInfo, error) {
	var minor C.OM_uint32
	var cGssName C.gss_name_t // cGssName allocated by GSSAPI; releaseed by *1
	var cTimeRec C.OM_uint32
	var cCredUsage C.gss_cred_usage_t
	var cMechs C.gss_OID_set // cActualMechs.elements allocated by GSSAPI; released by *2
	major := C.gss_inquire_cred(&minor, c.id, &cGssName, &cTimeRec, &cCredUsage, &cMechs)

	if major != 0 {
		return nil, makeStatus(major, minor)
	}

	// *2  release GSSAPI allocated array
	defer C.gss_release_oid_set(&minor, &cMechs)

	gssName := nameFromGssInternal(cGssName)

	// *1  release GSSAPI name
	defer gssName.Release()

	name, nameType, err := gssName.Display()
	if err != nil {
		return nil, err
	}

	ret := &g.CredInfo{
		Name:     name,
		NameType: nameType,
		Usage:    g.CredUsage(cCredUsage),
	}

	if cTimeRec != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRec != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRec)).Round(time.Second)
		}
		switch ret.Usage {
		default:
			ret.AcceptorExpiry = &t
			ret.InitiatorExpiry = &t
		case g.CredUsageAcceptOnly:
			ret.AcceptorExpiry = &t
		case g.CredUsageInitiateOnly:
			ret.InitiatorExpiry = &t
		}
	}

	actualMechOids := oidsFromGssOidSet(cMechs)
	for _, oid := range actualMechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			ret.Mechs = append(ret.Mechs, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, err
		}
	}

	return ret, nil
}

func (c *Credential) InquireByMech(mech g.GssMech) (*g.CredInfo, error) {
	mechOid := mech.Oid()

	var minor C.OM_uint32
	var cGssName C.gss_name_t // cGssName allocated by GSSAPI; releaseed by *1
	var cTimeRecInit, cTimeRecAcc C.OM_uint32
	var cCredUsage C.gss_cred_usage_t
	major := C.inquire_cred_by_mech(&minor, c.id, string(mechOid), &cGssName, &cTimeRecInit, &cTimeRecAcc, &cCredUsage)

	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	gssName := nameFromGssInternal(cGssName)

	// *1  release GSSAPI name
	defer gssName.Release()

	name, nameType, err := gssName.Display()
	if err != nil {
		return nil, err
	}

	ret := &g.CredInfo{
		Name:     name,
		NameType: nameType,
		Usage:    g.CredUsage(cCredUsage),
		Mechs:    []g.GssMech{mech},
	}

	if cTimeRecInit != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecInit != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecInit)).Round(time.Second)
		}
		ret.InitiatorExpiry = &t
	}
	if cTimeRecAcc != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecAcc != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecAcc)).Round(time.Second)
		}
		ret.AcceptorExpiry = &t
	}

	return ret, nil
}

func (c *Credential) Add(name g.GssName, mech g.GssMech, usage g.CredUsage, initiatorLifetime time.Duration, acceptorLifetime time.Duration) (*g.CredInfo, error) {
	mechOid := mech.Oid()

	var cGssName C.gss_name_t
	if name != nil {
		cName, ok := name.(*GssName)
		if !ok {
			return nil, fmt.Errorf("bad name type %T, %w", name, g.ErrBadName)
		}

		cGssName = cName.name
	}

	var minor C.OM_uint32
	var cTimeRecInit, cTimeRecAcc C.OM_uint32
	var cActualMechs C.gss_OID_set // cActualMechs.elements allocated by GSSAPI; released by *1
	major := C.add_cred(&minor, c.id, cGssName, string(mechOid), C.int(usage), C.OM_uint32(initiatorLifetime.Seconds()), C.OM_uint32(acceptorLifetime.Seconds()), &cActualMechs, &cTimeRecInit, &cTimeRecAcc)
	if major != 0 {
		return nil, makeMechStatus(major, minor, mech)
	}

	info := &g.CredInfo{
		Usage: usage,
	}
	if name != nil {
		var err error
		info.Name, info.NameType, err = name.Display()
		if err != nil {
			return nil, err
		}
	}

	actualMechOids := oidsFromGssOidSet(cActualMechs)
	for _, oid := range actualMechOids {
		mech, err := g.MechFromOid(oid)
		switch {
		default:
			info.Mechs = append(info.Mechs, mech)
		case errors.Is(err, g.ErrBadMech):
			// warn
			continue
		case err != nil:
			return nil, err
		}
	}

	if cTimeRecInit != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecInit != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecInit)).Round(time.Second)
		}
		info.InitiatorExpiry = &t
	}
	if cTimeRecAcc != C.GSS_C_INDEFINITE {
		var t time.Time
		if cTimeRecAcc != 0 {
			t = time.Now().Add(time.Second * time.Duration(cTimeRecAcc)).Round(time.Second)
		}
		info.AcceptorExpiry = &t
	}

	return info, nil
}
