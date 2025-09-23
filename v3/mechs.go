// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-oids.go -o mechs_gen.go
//go:generate  go run ../build-tools/gen-gss-mech-attrs.go -o mech_attrs_gen.go

// GssMech describes an available GSSAPI mechanism.
type GssMech interface {
	Oid() Oid
	OidString() string
	String() string
}

// gssMechImpl defines GSSAPI mechanisms
type gssMechImpl int

// Well known GSSAPI mechanisms
const (
	// Official Kerberos Mechanism (IETF)
	GSS_MECH_KRB5 gssMechImpl = iota
	GSS_MECH_IAKERB
	GSS_MECH_SPNEGO
	GSS_MECH_SPKM
	_GSS_MECH_LAST
)

type GssMechExtRFC5587 interface {
	GssMech
	InquireAttrs() ([]GssMechAttr, error) // RFC 5587 § 3.4.3
}

type GssMechAttr interface {
	Oid() Oid
	OidString() string
	String() string

	Display() (string, string, string, error) // RFC 5587 § 3.4.4
}

// Mechanism atttribbutes (RFC 5587)
type gssMechAttrImpl int

// Well known Mechanism attributes (RFC 5587)
const (
	GSS_MA_MECH_CONCRETE gssMechAttrImpl = iota
	GSS_MA_MECH_PSEUDO
	GSS_MA_MECH_COMPOSITE
	GSS_MA_MECH_NEGO
	GSS_MA_MECH_GLUE
	GSS_MA_NOT_MECH
	GSS_MA_DEPRECATED
	GSS_MA_NOT_DFLT_MECH
	GSS_MA_ITOK_FRAMED
	GSS_MA_AUTH_INIT
	GSS_MA_AUTH_TARG
	GSS_MA_AUTH_INIT_INIT
	GSS_MA_AUTH_TARG_INIT
	GSS_MA_AUTH_INIT_ANON
	GSS_MA_AUTH_TARG_ANON
	GSS_MA_DELEG_CRED
	GSS_MA_INTEG_PROT
	GSS_MA_CONF_PROT
	GSS_MA_MIC
	GSS_MA_WRAP
	GSS_MA_PROT_READY
	GSS_MA_REPLAY_DET
	GSS_MA_OOS_DET
	GSS_MA_CBINDINGS
	GSS_MA_PFS
	GSS_MA_COMPRESS
	GSS_MA_CTX_TRANS
	GSS_MA_NEGOEX_AND_SPNEGO

	_GSS_MA_LAST
)

func (mech gssMechImpl) Oid() Oid {
	if mech >= _GSS_MECH_LAST {
		panic(ErrBadMech)
	}

	return mechs[mech].oid
}

func (mech gssMechImpl) OidString() string {
	if mech >= _GSS_MECH_LAST {
		panic(ErrBadMech)
	}

	return mechs[mech].oidString
}

func (mech gssMechImpl) String() string {
	if mech >= _GSS_MECH_LAST {
		panic(ErrBadMech)
	}

	return mechs[mech].mech
}

func MechFromOid(oid Oid) (gssMechImpl, error) {
	for i, mech := range mechs {
		if slices.Equal(mech.oid, oid) {
			return gssMechImpl(i), nil
		}

		for _, alt := range mech.altOids {
			if slices.Equal(alt, oid) {
				return gssMechImpl(i), nil
			}
		}
	}

	return 0, ErrBadMech
}

func (attr gssMechAttrImpl) Oid() Oid {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].oid
}

func (attr gssMechAttrImpl) OidString() string {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].oidString
}

func (attr gssMechAttrImpl) String() string {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].mech
}

func (attr gssMechAttrImpl) Display() (string, string, string, error) {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].mech, mechAttrs[attr].shortDesc, mechAttrs[attr].longDesc, nil
}

func MechAttrFromOid(oid Oid) (gssMechAttrImpl, error) {
	for i, attr := range mechAttrs {
		if slices.Equal(attr.oid, oid) {
			return gssMechAttrImpl(i), nil
		}
	}

	return 0, ErrBadMechAttr
}
