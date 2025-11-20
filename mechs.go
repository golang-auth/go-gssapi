// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ./build-tools/gen-gss-mech-oids -o mechs_gen.go

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

// Well known GSSAPI mechanisms.  gssMechImpl is an internal type that implements
// the GssMech interface for these mechanisms.
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

// MechFromOid returns a mechanism implementation from an OID.
// The standard implementation offers this function for use with the gssMechImpl
// internal type for a standard set of well known mechanisms.
//
// If a provider needs to support a different mechanism, it can be added to gssMechImpl via a pull
// request to the go-gssapi repository. Alternatively, a new implementation of GssMech can be
// created for use by that GSSAPI implementation. Depending on the requirements, a replacement for
// MechFromOid may also need to be provided by the provider.
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
