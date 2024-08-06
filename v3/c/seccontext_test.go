package gssapi

import (
	"os"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3/interface"
	"github.com/stretchr/testify/assert"
)

type testAssets struct {
	ktfileRack string
	ktfileRuin string
	ccfile     string
	lib        g.Library

	saveVars saveVars
}

func mkTestAssets() *testAssets {
	ta := &testAssets{
		saveVars: newSaveVars("KRB5_KTNAME", "KRB5CCNAME"),
		lib:      New(),
	}

	ktName1, krName2, ccName, err := writeKrbCreds()
	if err != nil {
		panic(err)
	}

	ta.ktfileRack = ktName1
	ta.ktfileRuin = krName2
	ta.ccfile = ccName

	return ta
}

func (ta *testAssets) Free() {
	ta.saveVars.Restore()
	os.Remove(ta.ktfileRack)
	os.Remove(ta.ccfile)
}

func TestInitSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, outTok, err := ta.lib.InitSecContext(nil, name, 0, 0, 0)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	_, _, err = ta.lib.InitSecContext(nil, name, 0, 0, 0)
	assert.Error(err)
	assert.Contains(err.Error(), "Cannot find KDC")
}

func TestDeleteSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, outTok, err := ta.lib.InitSecContext(nil, name, 0, 0, 0)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)

	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)

	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)
}
