package gsscommon

import "slices"

//go:generate  go run ../build-tools/gen-gss-mech-oids.go -o mechs_gen.go

// GssMech defines GSSAPI mechanisms
type GssMech int

const (
	// Official Kerberos Mech (IETF)
	GSS_MECH_KRB5 GssMech = iota

	GSS_MECH_IAKERB

	GSS_MECH_SPNEGO
)

func (mech GssMech) Oid() Oid {
	if mech > GSS_MECH_SPNEGO {
		panic(ErrBadMech)
	}

	return mechs[mech].oid
}

func (mech GssMech) OidString() string {
	if mech > GSS_MECH_SPNEGO {
		panic(ErrBadMech)
	}

	return mechs[mech].oidString
}

func (mech GssMech) String() string {
	if mech > GSS_MECH_SPNEGO {
		panic(ErrBadMech)
	}

	return mechs[mech].mech
}

func MechFromOid(oid Oid) (GssMech, error) {
	for i, mech := range mechs {
		if slices.Equal(mech.oid, oid) {
			return GssMech(i), nil
		}

		for _, alt := range mech.altOids {
			if slices.Equal(alt, oid) {
				return GssMech(i), nil
			}
		}
	}

	return 0, ErrBadMech
}
