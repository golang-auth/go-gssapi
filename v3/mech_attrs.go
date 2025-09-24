// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-attrs.go -o mech_attrs_gen.go

// GssMechAttr represents mechanism attributes as defined in RFC 5587. The Go bindings support
// mechanism attributes for describing the capabilities and properties of GSSAPI mechanisms.
type GssMechAttr interface {
	// Oid returns the object identifier corresponding to the mechanism attribute.
	Oid() Oid
	// OidString returns a printable version of the object identifier associated with the mechanism attribute.
	OidString() string
	// String returns a printable version of the mechanism attribute name.
	String() string
	// Display returns human-readable information about the mechanism attribute as defined in RFC 5587 § 3.4.4.
	// Returns the attribute name, short description, and long description respectively.
	Display() (string, string, string, error) // RFC 5587 § 3.4.4
}

// gssMechAttrImpl defines mechanism attributes (RFC 5587). The standard implementation provides many well-known
// mechanism attributes including GSS_MA_MECH_CONCRETE, GSS_MA_MECH_PSEUDO, GSS_MA_MECH_COMPOSITE (Mechanism types),
// GSS_MA_AUTH_INIT, GSS_MA_AUTH_TARG (Authentication capabilities), GSS_MA_DELEG_CRED (Credential delegation support),
// GSS_MA_INTEG_PROT, GSS_MA_CONF_PROT (Protection services), GSS_MA_REPLAY_DET, GSS_MA_OOS_DET (Message ordering detection),
// GSS_MA_CBINDINGS (Channel binding support), and many others as defined in RFC 5587.
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

// MechAttrFromOid returns a mechanism attribute implementation from an OID.
// This function maps an OID to the corresponding mechanism attribute.
//
// Parameters:
//   - oid: the object identifier to look up
//
// Returns:
//   - gssMechAttrImpl: the corresponding mechanism attribute implementation
//   - error: ErrBadMechAttr if the OID is not recognized
func MechAttrFromOid(oid Oid) (gssMechAttrImpl, error) {
	for i, attr := range mechAttrs {
		if slices.Equal(attr.oid, oid) {
			return gssMechAttrImpl(i), nil
		}
	}

	return 0, ErrBadMechAttr
}
