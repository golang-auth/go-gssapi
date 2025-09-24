// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-oids.go -o mechs_gen.go
//go:generate  go run ../build-tools/gen-gss-mech-attrs.go -o mech_attrs_gen.go

// GssMech describes an available GSSAPI mechanism. GSSAPI mechanisms are identified by unique
// object identifiers (OIDs). The Go bindings define this interface for working with mechanisms.
type GssMech interface {
	// Oid returns the object identifier corresponding to the mechanism.
	Oid() Oid
	// OidString returns a printable version of the object identifier associated with the mechanism.
	OidString() string
	// String returns a printable version of the mechanism name.
	String() string
}

// gssMechImpl defines GSSAPI mechanisms. The gssMechImp implementation is provided as a convenience for provider implementations
// and clients of the interface. It supports the known mechanisms GSS_MECH_KRB5, GSS_MECH_IAKERB,
// GSS_MECH_SPNEGO, and GSS_MECH_SPKM.
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

// GssMechExtRFC5587 extends GssMech with RFC 5587 mechanism attribute functionality.
// Mechanisms implementing this interface can provide information about their attributes.
type GssMechExtRFC5587 interface {
	GssMech
	// InquireAttrs returns the attributes supported by this mechanism as defined in RFC 5587 § 3.4.3.
	InquireAttrs() ([]GssMechAttr, error) // RFC 5587 § 3.4.3
}

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

// MechFromOid returns a mechanism implementation from an OID. An implementation may need to obtain
// a GssMech from an OID. The standard implementation offers this function for use with gssMechImpl.
//
// If a provider needs to support a different mechanism, it can be added to gssMechImpl via a pull
// request to the go-gssapi repository. Alternatively, a new implementation of GssMech can be
// created for use by that GSSAPI implementation. Depending on the requirements, a replacement for
// MechFromOid may also need to be provided for the new mechanism.
//
// Parameters:
//   - oid: the object identifier to look up
//
// Returns:
//   - gssMechImpl: the corresponding mechanism implementation
//   - error: ErrBadMech if the OID is not recognized
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
