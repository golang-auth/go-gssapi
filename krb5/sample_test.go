package krb5

import (
	"encoding/binary"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Sample data from MIT Kerberos v1.19.1

// from src/tests/asn.1/ktest.h
const (
	SAMPLE_USEC           = 123456
	SAMPLE_SEQ_NUMBER     = 17
	SAMPLE_NONCE          = 42
	SAMPLE_FLAGS          = 0xFEDCBA98
	SAMPLE_ERROR          = 0x3C
	SAMPLE_PRINCIPAL_NAME = "hftsai/extra@ATHENA.MIT.EDU"
	SAMPLE_DATA           = "krb5data"
)

func ktest_make_sample_ap_rep_enc_part() encAPRepPart {
	tm, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	return encAPRepPart{
		CTime:          tm,
		Cusec:          SAMPLE_USEC,
		Subkey:         ktest_make_sample_keyblock(),
		SequenceNumber: SAMPLE_SEQ_NUMBER,
	}
}

func ktest_make_sample_keyblock() types.EncryptionKey {
	kv := []byte("12345678")
	return types.EncryptionKey{
		KeyType:  1,
		KeyValue: kv,
	}
}

func ktest_make_sample_enc_data() types.EncryptedData {
	return types.EncryptedData{
		EType:  0,
		KVNO:   5,
		Cipher: []byte(testdata.TEST_CIPHERTEXT),
	}
}

func ktest_make_sample_ticket() messages.Ticket {
	pn, realm := types.ParseSPNString(SAMPLE_PRINCIPAL_NAME)
	return messages.Ticket{
		TktVNO:  5,
		Realm:   realm,
		SName:   pn,
		EncPart: ktest_make_sample_enc_data(),
	}
}

func ktest_make_sample_ap_req() (aprep messages.APReq) {
	aprep = messages.APReq{
		PVNO:                   5,
		MsgType:                msgtype.KRB_AP_REQ,
		APOptions:              types.NewKrbFlags(),
		Ticket:                 ktest_make_sample_ticket(),
		EncryptedAuthenticator: ktest_make_sample_enc_data(),
	}

	binary.BigEndian.PutUint32(aprep.APOptions.Bytes[0:], SAMPLE_FLAGS)
	return
}

func ktest_make_sample_ap_rep() (aprep aPRep) {
	aprep = aPRep{
		PVNO:    5,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ktest_make_sample_enc_data(),
	}

	return
}

func ktest_make_sample_error() (krberr messages.KRBError) {
	pn, realm := types.ParseSPNString(SAMPLE_PRINCIPAL_NAME)
	tm, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	krberr = messages.KRBError{
		PVNO:      5,
		MsgType:   msgtype.KRB_ERROR,
		CTime:     tm,
		Cusec:     SAMPLE_USEC,
		STime:     tm,
		Susec:     SAMPLE_USEC,
		ErrorCode: SAMPLE_ERROR,
		CRealm:    realm,
		CName:     pn,
		Realm:     realm,
		SName:     pn,
		EText:     SAMPLE_DATA,
		EData:     []byte(SAMPLE_DATA),
	}

	return
}
