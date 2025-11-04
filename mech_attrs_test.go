// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for GssMechAttr type

func TestMechAttrOid(t *testing.T) {
	assert := assert.New(t)

	// Test valid mechanism attribute
	oid := GSS_MA_MECH_CONCRETE.Oid()
	expected := Oid{0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x01} // 1.3.6.1.5.5.13.1
	assert.Equal(expected, oid)

	// Test another valid attribute
	oid = GSS_MA_AUTH_INIT.Oid()
	expected = Oid{0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0a} // 1.3.6.1.5.5.13.10
	assert.Equal(expected, oid)

	// Test invalid mechanism attribute panics
	badAttr := gssMechAttrImpl(100)
	assert.PanicsWithValue(ErrBadMechAttr, func() { badAttr.Oid() })
}

func TestMechAttrOidString(t *testing.T) {
	assert := assert.New(t)

	// Test valid mechanism attribute
	oidStr := GSS_MA_MECH_CONCRETE.OidString()
	assert.Equal("1.3.6.1.5.5.13.1", oidStr)

	// Test another valid attribute
	oidStr = GSS_MA_DELEG_CRED.OidString()
	assert.Equal("1.3.6.1.5.5.13.16", oidStr)

	// Test invalid mechanism attribute panics
	badAttr := gssMechAttrImpl(100)
	assert.PanicsWithValue(ErrBadMechAttr, func() { _ = badAttr.OidString() })
}

func TestMechAttrString(t *testing.T) {
	assert := assert.New(t)

	// Test valid mechanism attribute
	str := GSS_MA_MECH_CONCRETE.String()
	assert.Equal("GSS_MA_MECH_CONCRETE", str)

	// Test another valid attribute
	str = GSS_MA_INTEG_PROT.String()
	assert.Equal("GSS_MA_INTEG_PROT", str)

	// Test invalid mechanism attribute panics
	badAttr := gssMechAttrImpl(100)
	assert.PanicsWithValue(ErrBadMechAttr, func() { _ = badAttr.String() })
}

func TestMechAttrDisplay(t *testing.T) {
	assert := assert.New(t)

	// Test valid mechanism attribute
	name, shortDesc, longDesc, err := GSS_MA_MECH_CONCRETE.Display()
	assert.NoError(err)
	assert.Equal("GSS_MA_MECH_CONCRETE", name)
	assert.Equal("concrete-mech", shortDesc)
	assert.Equal("Mechanism is neither a pseudo-mechanism nor a composite mechanism.", longDesc)

	// Test another valid attribute
	name, shortDesc, longDesc, err = GSS_MA_AUTH_INIT.Display()
	assert.NoError(err)
	assert.Equal("GSS_MA_AUTH_INIT", name)
	assert.Equal("auth-init-princ", shortDesc)
	assert.Equal("Mechanism supports authentication of initiator to acceptor.", longDesc)

	// Test invalid mechanism attribute panics
	badAttr := gssMechAttrImpl(100)
	assert.PanicsWithValue(ErrBadMechAttr, func() { _, _, _, _ = badAttr.Display() })
}

func TestMechAttrFromOid(t *testing.T) {
	assert := assert.New(t)

	// Test valid OID
	attr, err := MechAttrFromOid(Oid{0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x01}) // GSS_MA_MECH_CONCRETE
	assert.NoError(err)
	assert.Equal(GSS_MA_MECH_CONCRETE, attr)

	// Test another valid OID
	attr, err = MechAttrFromOid(Oid{0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x10}) // GSS_MA_DELEG_CRED
	assert.NoError(err)
	assert.Equal(GSS_MA_DELEG_CRED, attr)

	// Test invalid OID
	_, err = MechAttrFromOid(Oid{0x00, 0x01, 0x02})
	assert.ErrorIs(err, ErrBadMechAttr)

	// Test nil OID
	_, err = MechAttrFromOid(nil)
	assert.ErrorIs(err, ErrBadMechAttr)

	// Test empty OID
	_, err = MechAttrFromOid(Oid{})
	assert.ErrorIs(err, ErrBadMechAttr)
}
