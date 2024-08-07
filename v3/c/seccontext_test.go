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

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	// no continue should be needed when we don't request mutual auth
	secCtx, outTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)
	assert.False(secCtx.ContinueNeeded())

	// .. but should be needed if we do request mutual auth
	secCtx, outTok, err = ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)
	assert.True(secCtx.ContinueNeeded())

	// This one should not work because the CC doesn't have a ticket for ruin/bar.golang-auth.io@GOLANG-AUTH.IO
	// and there are no KDCs defined that can get us a ticket
	name, err = ta.lib.ImportName("ruin@bar.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	_, _, err = ta.lib.InitSecContext(name)
	assert.Error(err)
	assert.Contains(err.Error(), "Cannot find KDC")
}

func TestAcceptSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// InitSecContext with this name should work because the cred-cache has a ticket
	// for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	// the initiator token should be accepted by AcceptSecContext because we have a keytab
	// for the service princ.  The output token should be empty because the initiator
	// didn't request  mutual auth
	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok)
	assert.NoError(err)
	assert.Empty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())

	// if we're doing mutual auth we should get an output token from the acceptor but it
	// should not need another one back from the initiator
	secCtxInitiator, initiatorTok, err = ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.True(secCtxInitiator.ContinueNeeded())

	secCtxAcceptor, acceptorTok, err = ta.lib.AcceptSecContext(nil, initiatorTok)
	assert.NoError(err)
	assert.NotEmpty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())
}

func TestDeleteSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtx, outTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(outTok)
	assert.NotNil(secCtx)

	// deleting a live or a deleted context should not return errors
	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)

	_, err = secCtx.Delete()
	assert.NoError(err)
	assert.Nil(secCtx.(*SecContext).id)
}

func TestContextExpiresAt(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok)
	assert.NoError(err)
	assert.Empty(acceptorTok)
	assert.NotNil(secCtxAcceptor)
	assert.False(secCtxAcceptor.ContinueNeeded())

	// both the initiator and the acceptor should know about the expiry time
	tm, err := secCtxInitiator.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())

	tm, err = secCtxAcceptor.ExpiresAt()
	assert.NoError(err)
	assert.Equal(2051, tm.Year())
}

func TestContextWrapSizeLimit(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	o := g.WithInitiatorFlags(g.ContextFlagInteg | g.ContextFlagConf)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, o)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtxInitiator)
	assert.False(secCtxInitiator.ContinueNeeded())

	// the max unwrapped token size would always be less that the max
	// wrapped token size
	tokSize, err := secCtxInitiator.WrapSizeLimit(true, 100)
	assert.NoError(err)
	assert.Less(tokSize, uint32(1000))
}

func TestExportImportSecContext(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)
	// This should work because the cred-cache has a ticket for rack/foo.golang-auth.io@GOLANG-AUTH.IO
	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)
	secCtx, initiatorTok, err := ta.lib.InitSecContext(name)
	assert.NoError(err)
	assert.NotEmpty(initiatorTok)
	assert.NotNil(secCtx)
	assert.False(secCtx.ContinueNeeded())

	_, err = secCtx.Inquire() // should work the first time
	assert.NoError(err)

	tok, err := secCtx.Export() // exported context invalidates the original
	assert.NoError(err)
	assert.NotEmpty(tok)

	_, err = secCtx.Inquire() // so this should fail
	assert.ErrorIs(err, g.ErrNoContext)

	// try to import the context
	newCtx, err := ta.lib.ImportSecContext(tok)
	assert.NoError(err)
	_, err = newCtx.Inquire() // should work again here
	assert.NoError(err)

}

func TestSecContextEstablishment(t *testing.T) {
	assert := assert.New(t)

	ta := mkTestAssets()

	os.Setenv("KRB5_KTNAME", ta.ktfileRack)
	os.Setenv("KRB5CCNAME", "FILE:"+ta.ccfile)

	name, err := ta.lib.ImportName("rack@foo.golang-auth.io", g.GSS_NT_HOSTBASED_SERVICE)
	assert.NoError(err)

	secCtxInitiator, initiatorTok, err := ta.lib.InitSecContext(name, g.WithInitiatorFlags(g.ContextFlagMutual))
	assert.NoError(err)

	secCtxAcceptor, acceptorTok, err := ta.lib.AcceptSecContext(nil, initiatorTok)
	assert.NoError(err)

	for secCtxInitiator.ContinueNeeded() {
		initiatorTok, err = secCtxInitiator.Continue(acceptorTok)
		assert.NoError(err)

		if len(initiatorTok) > 0 {
			acceptorTok, err = secCtxAcceptor.Continue(initiatorTok)
			assert.NoError(err)
		}
	}

	assert.False(secCtxAcceptor.ContinueNeeded())

	msg := []byte("Hello GSSAPI")
	wrapped, hasConf, err := secCtxInitiator.Wrap(msg, true)
	assert.NoError(err)
	assert.True(hasConf)
	assert.NotEmpty(wrapped)

	unwrapped, hasConf, err := secCtxAcceptor.Unwrap(wrapped)
	assert.NoError(err)
	assert.True(hasConf)
	assert.Equal(msg, unwrapped)

	mic, err := secCtxInitiator.GetMIC(msg)
	assert.NoError(err)
	assert.NotEmpty(mic)

	err = secCtxAcceptor.VerifyMIC(msg, mic)
	assert.NoError(err)
}
