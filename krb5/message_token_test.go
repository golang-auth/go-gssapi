package krb5

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/stretchr/testify/assert"

	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	TEST_WRAP_PAYLOAD = "testing 123"

	// from kadmin:
	//   ank -kvno 123 -pw password -e test test
	//   ktadd -k test.kt -norandkey test
	TEST_AES256_KVNO = 123
	TEST_AES256_KEY  = "93860ea9a3961f58f1e1370286c720ab8da6574cacb26396f7de6ebfbbfd00a0"
	AES_CKSUM_LEN    = 12
	ENC_PAYLOAD_LEN  = 55

	SAMPLE_WRAP_TOKEN_SIGNATURE      = "71914A5D08018A97375AB52A"
	WRAP_TOKEN_SIGNED_HEADER         = "050400ff000c0000000000000000007B"
	SAMPLE_SIGNED_WRAP_TOKEN         = "050404ff000c000000000000209bb2cb74657374696e6720313233efed11aa6caa6cf5a7e595a5"
	SAMPLE_SIGNED_WRAP_TOKEN_WINDOWS = "050400ff000c000c0000000000000000a79b6be6ce749f2f6102c78774657374"
	SAMPLE_MIC_TOKEN_SIGNATURE       = "b479cc6b1a27beb60a815b26"
	MIC_TOKEN_HEADER                 = "040404ffffffffff000000000000007B"
	SAMPLE_MIC_TOKEN                 = "040404ffffffffff000000000000007Bb479cc6b1a27beb60a815b26"
)

func mk_sample_wrap_token(sealed bool) (wt WrapToken) {
	return WrapToken{
		Flags:          0,
		SequenceNumber: 123,
		Payload:        []byte(TEST_WRAP_PAYLOAD),
	}
}

func mk_sample_mic_token(sealed bool) (mt MICToken) {
	return MICToken{
		Flags:          4,
		SequenceNumber: 123,
	}
}

func mk_sample_aes_key() (key types.EncryptionKey) {
	b, _ := hex.DecodeString(TEST_AES256_KEY)
	return types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: b,
	}
}

func TestWrapTokenSign(t *testing.T) {
	key := mk_sample_aes_key()
	tok := mk_sample_wrap_token(false)

	err := tok.Sign(key)

	assert.NoError(t, err, "signing operation failed")
	assert.True(t, tok.signedOrSealed, "token was not signed")
	assert.Equal(t, uint16(AES_CKSUM_LEN), tok.EC, "wrong checksum length")
	assert.Equal(t, len(TEST_WRAP_PAYLOAD)+AES_CKSUM_LEN, len(tok.Payload), "wrong signed payload length")

	want_sig, _ := hex.DecodeString(SAMPLE_WRAP_TOKEN_SIGNATURE)
	assert.Equal(t, want_sig, tok.Payload[len(TEST_WRAP_PAYLOAD):], "signature not as expected")
	assert.Equal(t, []byte(TEST_WRAP_PAYLOAD), tok.Payload[0:len(TEST_WRAP_PAYLOAD)], "corrupt payload")
}

func TestWrapTokenSeal(t *testing.T) {
	key := mk_sample_aes_key()
	tok := mk_sample_wrap_token(false)

	err := tok.Seal(key)

	assert.NoError(t, err, "sealing operation failed")
	assert.True(t, tok.signedOrSealed, "token was not sealed")
	assert.Equal(t, uint16(0), tok.EC, "wrong extra-count")
	assert.Equal(t, ENC_PAYLOAD_LEN, len(tok.Payload), "sealed token length is wrong")
}

func TestWrapTokenMarshal(t *testing.T) {
	key := mk_sample_aes_key()
	tok := mk_sample_wrap_token(false)

	_, err := tok.Marshal()
	assert.Error(t, err, "Marshal of unsigned/sealed token should be an error")

	err = tok.Sign(key)
	assert.NoError(t, err, "signing operation failed")

	tokBytes, err := tok.Marshal()
	assert.NoError(t, err, "Marshal of signed token should succeed")
	assert.Equal(t, 16+len(TEST_WRAP_PAYLOAD)+AES_CKSUM_LEN, len(tokBytes), "bad token length")

	want_header, _ := hex.DecodeString(WRAP_TOKEN_SIGNED_HEADER)
	assert.Equal(t, want_header, tokBytes[0:16], "bad wrap token header")

	want_sig, _ := hex.DecodeString(SAMPLE_WRAP_TOKEN_SIGNATURE)
	assert.Equal(t, []byte(TEST_WRAP_PAYLOAD), tokBytes[16:16+len(TEST_WRAP_PAYLOAD)], "corrupt payload")
	assert.Equal(t, want_sig, tokBytes[16+len(TEST_WRAP_PAYLOAD):], "signature not as expected")
}

func TestWrapTokenUnmarshal(t *testing.T) {
	tokBytes, _ := hex.DecodeString(SAMPLE_SIGNED_WRAP_TOKEN)

	tok := WrapToken{}
	err := tok.Unmarshal(tokBytes)
	assert.NoError(t, err, "Unmarshal of signed token failed")

	assert.Equal(t, 0x04, int(tok.Flags), "bad token flags")
	assert.Equal(t, uint16(AES_CKSUM_LEN), tok.EC, "bad EC (signature length)")
	assert.Equal(t, uint16(0), tok.RRC, "bad RRC")
	assert.Equal(t, uint64(0x209bb2cb), tok.SequenceNumber, "bad sequence number")
	assert.Equal(t, true, tok.signedOrSealed, "token is not signed/sealed")
}

func TestWindowsWrapTokenUnmarshal(t *testing.T) {
	tokBytes, _ := hex.DecodeString(SAMPLE_SIGNED_WRAP_TOKEN_WINDOWS)

	tok := WrapToken{}
	err := tok.Unmarshal(tokBytes)
	assert.NoError(t, err, "Unmarshal of signed token failed")

	assert.Equal(t, 0x00, int(tok.Flags), "bad token flags")
	assert.Equal(t, uint16(AES_CKSUM_LEN), tok.EC, "bad EC (signature length)")
	assert.Equal(t, uint16(12), tok.RRC, "bad RRC")
	assert.Equal(t, uint64(0), tok.SequenceNumber, "bad sequence number")
	assert.Equal(t, true, tok.signedOrSealed, "token is not signed/sealed")
}

func TestRotateLeft(t *testing.T) {
	var testData = "abcdefghijklmnop"

	var tests = []struct {
		rc       uint
		expected string
	}{
		{0, "abcdefghijklmnop"},
		{1, "bcdefghijklmnopa"},
		{15, "pabcdefghijklmno"},
		{16, "abcdefghijklmnop"},
		{17, "bcdefghijklmnopa"},
		{32, "abcdefghijklmnop"},
		{33, "bcdefghijklmnopa"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("rc=%d", tt.rc), func(t *testing.T) {
			in := testData
			out := rotateLeft([]byte(in), tt.rc)
			assert.Equal(t, tt.expected, string(out))
		})
	}
}

func TestMICTokenSign(t *testing.T) {
	key := mk_sample_aes_key()
	tok := mk_sample_mic_token(false)

	err := tok.Sign([]byte(TEST_WRAP_PAYLOAD), key)

	assert.NoError(t, err, "signing operation failed")
	assert.True(t, tok.signed, "token was not signed")

	want_sig, _ := hex.DecodeString(SAMPLE_MIC_TOKEN_SIGNATURE)
	assert.Equal(t, want_sig, tok.Checksum, "signature not as expected")
}

func TestMICTokenMarshal(t *testing.T) {
	key := mk_sample_aes_key()
	tok := mk_sample_mic_token(false)

	_, err := tok.Marshal()
	assert.Error(t, err, "Marshal of unsigned MIC token should be an error")

	err = tok.Sign([]byte(TEST_WRAP_PAYLOAD), key)
	assert.NoError(t, err, "signing operation failed")

	tokBytes, err := tok.Marshal()
	assert.NoError(t, err, "Marshal of signed token should succeed")
	assert.Equal(t, 16+AES_CKSUM_LEN, len(tokBytes), "bad token length")

	want_header, _ := hex.DecodeString(MIC_TOKEN_HEADER)
	assert.Equal(t, want_header, tokBytes[0:16], "bad MIC token header")

	want_sig, _ := hex.DecodeString(SAMPLE_MIC_TOKEN_SIGNATURE)
	assert.Equal(t, want_sig, tokBytes[16:], "signature not as expected")
}

func TestMICTokenUnmarshal(t *testing.T) {
	tokBytes, _ := hex.DecodeString(SAMPLE_MIC_TOKEN)

	tok := MICToken{}
	err := tok.Unmarshal(tokBytes)
	assert.NoError(t, err, "Unmarshal of MIC token failed")

	assert.Equal(t, 0x04, int(tok.Flags), "bad token flags")
	assert.Equal(t, uint64(123), tok.SequenceNumber, "bad sequence number")
	assert.Equal(t, true, tok.signed, "token is not signed/sealed")
}
