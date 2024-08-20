// SPDX-License-Identifier: Apache-2.0
package gssapi

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-oids.go -o mechs_gen.go

type GssMech interface {
	Oid() Oid
	OidString() string
	String() string
}

// gssMechImpl defines GSSAPI mechanisms
type gssMechImpl int

const (
	// Official Kerberos Mech (IETF)
	GSS_MECH_KRB5 gssMechImpl = iota

	GSS_MECH_IAKERB

	GSS_MECH_SPNEGO

	GSS_MECH_SPKM
)

func (mech gssMechImpl) Oid() Oid {
	if mech > GSS_MECH_SPNEGO {
		panic(ErrBadMech)
	}

	return mechs[mech].oid
}

func (mech gssMechImpl) OidString() string {
	if mech > GSS_MECH_SPNEGO {
		panic(ErrBadMech)
	}

	return mechs[mech].oidString
}

func (mech gssMechImpl) String() string {
	if mech > GSS_MECH_SPNEGO {
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
