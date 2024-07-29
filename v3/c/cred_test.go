package gssapi

import (
	"os"
	"testing"

	g "github.com/golang-auth/go-gssapi/v3/interface"
	"github.com/stretchr/testify/assert"
)

// ktdata is a Kerberos keytab for service/some.host@JAKETHESNAKE.DEV
var ktdata = `
BQIAAABZAAIAEEpBS0VUSEVTTkFLRS5ERVYAB3NlcnZpY2UACXNvbWUuaG9zdAAAAAFmqs1SAgAS
ACD/EfDF9Xe4tIuJTRHXMX/6XcX6tBJoPfeyFQzEiTldQQAAAAIAAABJAAIAEEpBS0VUSEVTTkFL
RS5ERVYAB3NlcnZpY2UACXNvbWUuaG9zdAAAAAFmqs1SAgARABDtv9qs3p9IJ/RSluQBTMcKAAAA
Ag==
`

const spname = "service/some.host@JAKETHESNAKE.DEV"

// ccdata is a Kerberos credentials cache for client principal robot@JAKETHESNAKE.DEV
// with an expiry date of 2051-12-17 19:09:51
var ccdata = `
BQQADAABAAgAAAAAAAAAAAAAAAEAAAABAAAAEEpBS0VUSEVTTkFLRS5ERVYAAAAFcm9ib3QAAAAB
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

func TestAcquireCredential(t *testing.T) {
	assert := assert.New(t)

	lib := New()

	//os.Setenv("KRB5_KTNAME", "/home/jacob/src/github.com/golang-auth/go-gssapi/v3/t/test.kt")
	os.Setenv("KRB5CCNAME", "/home/jacob/src/github.com/golang-auth/go-gssapi/v3/t/robot.cc")
	// name, err := lib.ImportName("service/some.host@JAKETHESNAKE.DEV", g.GSS_NO_OID)
	// assert.NoError(err)
	// defer name.Release()

	cred, err := lib.AcquireCredential(nil, 0, nil, g.CredUsageInitiateAndAccept)
	assert.NoError(err)
	_ = cred
}
