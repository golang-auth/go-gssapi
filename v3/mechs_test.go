// SPDX-License-Identifier: Apache-2.0
package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMechOid(t *testing.T) {
	assert := assert.New(t)

	// octal literal is from the MIT source code (src/lib/gssapi/krb5/gssapiP_krb5.h)
	oid := GSS_MECH_KRB5.Oid()
	assert.Equal(Oid{052, 0206, 0110, 0206, 0367, 0022, 0001, 0002, 0002}, oid)

	badMech := gssMechImpl(100)
	assert.PanicsWithValue(ErrBadMech, func() { badMech.Oid() })
}

func TestMechOidString(t *testing.T) {
	assert := assert.New(t)

	oid := GSS_MECH_IAKERB.OidString()
	assert.Equal("1.3.6.1.5.2.5", oid)

	badMech := gssMechImpl(100)
	assert.PanicsWithValue(ErrBadMech, func() { badMech.OidString() })
}

func TestMechString(t *testing.T) {
	assert := assert.New(t)

	oid := GSS_MECH_SPNEGO.String()
	assert.Equal("GSS_MECH_SPNEGO", oid)

	badMech := gssMechImpl(100)
	assert.PanicsWithValue(ErrBadMech, func() { badMech.String() })
}

func TestMechFromOid(t *testing.T) {
	assert := assert.New(t)

	// from a good primary OID
	mech, err := MechFromOid(Oid{0x2b, 0x6, 0x1, 0x5, 0x2, 0x5})
	assert.NoError(err)
	assert.Equal(GSS_MECH_IAKERB, mech)

	// from a secondary OID
	mech, err = MechFromOid(Oid{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x1, 0x2, 0x2})
	assert.NoError(err)
	assert.Equal(GSS_MECH_KRB5, mech)

	// from a bad oid
	_, err = MechFromOid(Oid{0x00})
	assert.ErrorIs(err, ErrBadMech)

	// from a nil oid
	_, err = MechFromOid(nil)
	assert.ErrorIs(err, ErrBadMech)
}
