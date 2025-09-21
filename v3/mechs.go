// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-oids.go -o mechs_gen.go

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
