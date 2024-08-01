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

// ktdata is a Kerberos keytab for service/some.host@JAKETHESNAKE.DEV
var ktdata = `BQIAAABZAAIAEEpBS0VUSEVTTkFLRS5ERVYAB3NlcnZpY2UACXNvbWUuaG9zdAAAAAFmqs1SAgAS
ACD/EfDF9Xe4tIuJTRHXMX/6XcX6tBJoPfeyFQzEiTldQQAAAAIAAABJAAIAEEpBS0VUSEVTTkFL
RS5ERVYAB3NlcnZpY2UACXNvbWUuaG9zdAAAAAFmqs1SAgARABDtv9qs3p9IJ/RSluQBTMcKAAAA
Ag==
`

const spname = "service/some.host@JAKETHESNAKE.DEV"

// ccdata is a Kerberos credentials cache for client principal robot@JAKETHESNAKE.DEV
// containing a TGT with expiry date of 2051-12-17 19:09:51
var ccdata = `BQQADAABAAgAAAAAAAAAAAAAAAEAAAABAAAAEEpBS0VUSEVTTkFLRS5ERVYAAAAFcm9ib3QAAAAB
AAAAAQAAABBKQUtFVEhFU05BS0UuREVWAAAABXJvYm90AAAAAQAAAAMAAAAMWC1DQUNIRUNPTkY6
AAAAFWtyYjVfY2NhY2hlX2NvbmZfZGF0YQAAAApmYXN0X2F2YWlsAAAAKGtyYnRndC9KQUtFVEhF
U05BS0UuREVWQEpBS0VUSEVTTkFLRS5ERVYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAN5ZXMAAAAAAAAAAQAAAAEAAAAQSkFLRVRIRVNOQUtFLkRFVgAAAAVyb2JvdAAAAAIA
AAACAAAAEEpBS0VUSEVTTkFLRS5ERVYAAAAGa3JidGd0AAAAEEpBS0VUSEVTTkFLRS5ERVYAEgAA
ACBfwEEGx/17PdvxZalWJJtRV8JkaXhLkqs0Po/EoIVLrGaq0k9mqtJPmipqTwAAAAAAAEEAAAAA
AAAAAAAAAAABUGGCAUwwggFIoAMCAQWhEhsQSkFLRVRIRVNOQUtFLkRFVqIlMCOgAwIBAqEcMBob
BmtyYnRndBsQSkFLRVRIRVNOQUtFLkRFVqOCAQQwggEAoAMCARKhAwIBAaKB8wSB8NJeIBtjnWEu
KREfkLyv+IsNULoVev5+6vUfL2obibd4HMUg7dSFYn5PMxu/g71yRcdqe85njEBoZnmUHHGOd5r+
OVu84b9rC7WePt5gQrIf071OFLr45zeX9zviu0TxKeRNKT+XNEKRe9jmrzuDzDaV1lu7QUdW0G89
dthwf3ZoKZIvgwwp7qduD7uPAwvbvanjDx83BqgI9/P0+9GuVnfj6l4uM6TLp4j0SSvDme48GZW9
NyGmR6rFgAqOnpLxeYfG9k/y9yWpvSRiKyIRcSZfRa++3jUDR16j9ZBW5U0GJVqdPUivvDyjp1Qx
PPwL5QAAAAA=
`

const cliname = "robot@JAKETHESNAKE.DEV"

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

func writeKrbCreds() (kt, cc string, err error) {
	kt, err = writeTmpBase64(ktdata)
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

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// Try to acquire creds for initiate and accept when we only have a valid
	// keytab -- only 'accept' should work

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:/tmp/no-such-file")

	_, info, err := lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	assert.Equal("", info.Name)
	assert.ElementsMatch(info.Mechs, mechs)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again but only with a credentials cache -- only initiate should work
	os.Setenv("KRB5_KTNAME", "/tmp/no-such/file")
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try again with a credentials cache and keytab -- both should work
	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	_, _, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.NoError(err)

}

func TestAcquireCredentialWithName(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	nameInitiator, err := lib.ImportName(cliname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)
	nameAcceptor, err := lib.ImportName(spname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	assert.NoError(err)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Try to acquire creds for the initiator name -- should only work for
	// the initator(!)
	_, _, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageAcceptOnly, 0)
	assert.Error(err)
	_, info, err := lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	assert.Equal(cliname, info.Name)
	_, _, err = lib.AcquireCredential(nameInitiator, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)

	// Try to acquire for the acceptor
	_, info, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	assert.Equal(spname, info.Name)
	_, _, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateOnly, 0)
	assert.Error(err)
	_, _, err = lib.AcquireCredential(nameAcceptor, mechs, g.CredUsageInitiateAndAccept, 0)
	assert.Error(err)
}

func TestAcquireCredentialWithLifetime(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	lifetime := time.Hour

	// We'll only get an expiry when requesting creds for the initiator, when it
	// is the expiry time of the TGT (sometime in 2051.. )

	_, info, err := lib.AcquireCredential(nil, mechs, g.CredUsageAcceptOnly, lifetime)
	assert.NoError(err)
	assert.Nil(info.InitiatorExpiry)
	assert.Nil(info.AcceptorExpiry)

	_, info, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, lifetime)
	assert.NoError(err)
	assert.Equal(2051, info.InitiatorExpiry.Year())
	assert.Nil(info.AcceptorExpiry)

	_, info, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateAndAccept, lifetime)
	assert.NoError(err)
	assert.Equal(2051, info.InitiatorExpiry.Year())
	assert.Equal(2051, info.AcceptorExpiry.Year())
}

func TestAcquireCredentialWithDefaultMech(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5_KTNAME", "KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5_KTNAME", ktName)
	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	_, info, err := lib.AcquireCredential(nil, nil, g.CredUsageAcceptOnly, 0)
	assert.NoError(err)
	assert.NotZero(len(info.Mechs))
	assert.Equal(g.CredUsageAcceptOnly, info.Usage)

	_, info, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	assert.NotZero(len(info.Mechs))
	assert.Equal(g.CredUsageInitiateOnly, info.Usage)

	_, info, err = lib.AcquireCredential(nil, nil, g.CredUsageInitiateAndAccept, 0)
	assert.NoError(err)
	assert.NotZero(len(info.Mechs))
	assert.Equal(g.CredUsageInitiateAndAccept, info.Usage)
}

func TestAcquireCredentialMechResult(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// Kerberos mech only
	mechs := []g.GssMech{g.GSS_MECH_KRB5}
	cred, info, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	assert.ElementsMatch(mechs, info.Mechs)
	defer cred.Release()

	// Kerb and SPNEGO
	mechs = []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO}
	cred, info, err = lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	assert.ElementsMatch(mechs, info.Mechs)
	defer cred.Release()

}

func TestInquireCredential(t *testing.T) {
	assert := assert.New(t)
	vars := newSaveVars("KRB5CCNAME")
	defer vars.Restore()

	lib := New()

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, _, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	info, err := cred.Inquire()
	assert.NoError(err)

	assert.Equal("robot@JAKETHESNAKE.DEV", info.Name)
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

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, _, err := lib.AcquireCredential(nil, nil, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	info, err := cred.InquireByMech(g.GSS_MECH_KRB5)
	assert.NoError(err)

	assert.Equal("robot@JAKETHESNAKE.DEV", info.Name)
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

	ktName, ccName, err := writeKrbCreds()
	assert.NoError(err)
	defer os.Remove(ktName)
	defer os.Remove(ccName)

	os.Setenv("KRB5CCNAME", "FILE:"+ccName)

	// nameInitiator, err := lib.ImportName(cliname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	// assert.NoError(err)
	// nameAcceptor, err := lib.ImportName(spname, g.GSS_KRB5_NT_PRINCIPAL_NAME)
	// assert.NoError(err)

	mechs := []g.GssMech{g.GSS_MECH_KRB5}

	// grab the default initiate cred -- which will be the TGT from the sample cred-cache
	cred, _, err := lib.AcquireCredential(nil, mechs, g.CredUsageInitiateOnly, 0)
	assert.NoError(err)
	defer cred.Release()

	// then try adding the SPNEGO mech
	info, err := cred.Add(nil, g.GSS_MECH_SPNEGO, g.CredUsageInitiateOnly, 0, 0)
	assert.NoError(err)
	assert.ElementsMatch(info.Mechs, []g.GssMech{g.GSS_MECH_KRB5, g.GSS_MECH_SPNEGO})
}
