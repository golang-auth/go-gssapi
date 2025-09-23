// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNtOid(t *testing.T) {
	assert := assert.New(t)

	oid := GSS_NT_HOSTBASED_SERVICE.Oid()
	assert.Equal(Oid{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04}, oid)

	oid = GSS_NO_NAME.Oid()
	assert.Nil(oid)

	oid = GSS_NT_USER_NAME.Oid()
	assert.Equal(Oid{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01}, oid)

	badNt := GssNameType(100)
	assert.PanicsWithValue(ErrBadNameType, func() { _ = badNt.Oid() })
}

func TestNtOidString(t *testing.T) {
	assert := assert.New(t)

	oid := GSS_NT_HOSTBASED_SERVICE.OidString()
	assert.Equal("1.2.840.113554.1.2.1.4", oid)

	oid = GSS_NO_NAME.OidString()
	assert.Equal("", oid)

	oid = GSS_NT_USER_NAME.OidString()
	assert.Equal("1.2.840.113554.1.2.1.1", oid)

	badNt := GssNameType(100)
	assert.PanicsWithValue(ErrBadNameType, func() { _ = badNt.OidString() })
}

func TestNtString(t *testing.T) {
	assert := assert.New(t)

	oid := GSS_NT_HOSTBASED_SERVICE.String()
	assert.Equal("GSS_NT_HOSTBASED_SERVICE", oid)

	oid = GSS_NO_NAME.String()
	assert.Equal("GSS_NO_NAME", oid)

	oid = GSS_NT_USER_NAME.String()
	assert.Equal("GSS_NT_USER_NAME", oid)

	badNt := GssNameType(100)
	assert.PanicsWithValue(ErrBadNameType, func() { _ = badNt.String() })
}

func TestNameFromOid(t *testing.T) {
	assert := assert.New(t)

	// from a good primary OID
	nt, err := NameFromOid(Oid{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01})
	assert.NoError(err)
	assert.Equal(GSS_NT_USER_NAME, nt)

	// from a secondary OID
	nt, err = NameFromOid(Oid{0x2B, 0x06, 0x01, 0x05, 0x06, 0x02})
	assert.NoError(err)
	assert.Equal(GSS_NT_HOSTBASED_SERVICE, nt)

	nt, err = NameFromOid(Oid{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02})
	assert.NoError(err)
	assert.Equal(GSS_KRB5_NT_PRINCIPAL_NAME, nt)

	// from a bad oid
	_, err = NameFromOid(Oid{0x00})
	assert.ErrorIs(err, ErrBadNameType)

	// from a nil oid
	nt, err = NameFromOid(nil)
	assert.NoError(err)
	assert.Equal(GSS_NO_OID, nt)
}
