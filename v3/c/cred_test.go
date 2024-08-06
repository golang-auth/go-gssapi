package gssapi

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	g "github.com/golang-auth/go-gssapi/v3/interface"
	"github.com/stretchr/testify/assert"
)

func writeTmpBase64(b64 string) (string, error) {
	r := strings.NewReader(b64)
	decoder := base64.NewDecoder(base64.StdEncoding, r)
	return writeTmp(decoder)
}

func writeTmp(r io.Reader) (string, error) {
	fh, err := os.CreateTemp("", "test")
	if err != nil {
		return "", err
	}

	fn := fh.Name()
	_, err = io.Copy(fh, r)
	fh.Close()

	return fn, err
}

func writeKrbCreds() (kt1, kt2, cc string, err error) {
	kt1, err = writeTmpBase64(ktdata1)
	if err != nil {
		return
	}
	kt2, err = writeTmpBase64(ktdata2)
	if err != nil {
		return
	}

	cc, err = writeTmpBase64(ccdata)

	return
}

func TestAcquireCredentialDefaultName(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// Try to acquire creds for initiate and accept when we only have a valid
	// keytab -- only 'accept' should work

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:/tmp/no-such-file")

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	os.Setenv("KRB5_KTNAME", "/tmp/no-such/file")
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again with a credentials cache and keytab -- both should work
	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.NoError(err)

}

func TestAcquireCredentialWithName(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	nameInitiator, err := lib.ImportName(cliname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)
	nameAcceptor, err := lib.ImportName(spname1, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Try to acquire creds for the initiator name -- should only work for
	// the initator(!)
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try to acquire for the acceptor
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)
}

func TestAcquireCredentialWithLifetime(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	lifetime := time.Hour

	// We'll only get an expiry when requesting creds for the initiator, when it
	// is the expiry time of the TGT (sometime in 2051.. )

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, lifetime)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, lifetime)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, lifetime)
	assert.NoError(err)
}

func TestAcquireCredentialWithDefaultMech(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, err = lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)

	_, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateAndAccept, 0)
	assert.NoError(err)
}

func TestAcquireCredentialMechResult(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Kerberos mech only
	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	cred, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	// Kerb and SPNEGO
	mechs = []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}
	cred, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

}

func TestInquireCredential(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	info, err := cred.Inquire()
	assert.NoError(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
	assert.Equal(2051, info.InitiatorExpiry.Year())
	assert.Nil(info.AcceptorExpiry)
}

func TestInquireCredentialByMech(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	info, err := cred.InquireByMech(g.GSS_MECH_KRB5)
	assert.NoError(err)

	assert.Equal("robot@GOLANG-AUTH.IO", info.Name)
	assert.Equal(g.GSS_KRB5_NT_PRINCIPAL_NAME, info.NameType)
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)
	assert.Equal(2051, info.InitiatorExpiry.Year())
	assert.Equal(&time.Time{}, info.AcceptorExpiry)
}

func TestAddCredential(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, _, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	info, err := cred.Inquire()
	assert.NoError(err)
	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5}, info.Mechs)

	// then try adding the SPNEGO mech
	err = cred.Add(nil, g.GSS_MECH_SPNEGO, g.CredUsageInitiateOnly, 0, 0)
	assert.NoError(err)

	info, err = cred.Inquire()
	assert.NoError(err)

	assert.ElementsMatch([]g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}, info.Mechs)
}
