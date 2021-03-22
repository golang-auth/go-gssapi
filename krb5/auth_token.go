package krb5

/*
 * Derived from github.com/jcmturner/gokrb5/v8/spnego/krb5Token.go
 *
 * The modified version adds functionality to marshal an APReq message
 * to be used as part of a mutually-authenticated GSSAPI security
 * context; verification is moved out.
 */

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/messages"

	"github.com/jake-scott/go-gssapi"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// kRB5Token context token implementation for GSSAPI.
type kRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    *messages.APReq
	APRep    *aPRep
	KRBError *messages.KRBError
}

// marshal a KRB5Token into a slice of bytes.
func (m *kRB5Token) marshal() (outTok []byte, err error) {
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			err = fmt.Errorf("gssapi: error marshalling AP-REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		tb, err = m.APRep.marshal()
		if err != nil {
			err = fmt.Errorf("gssapi: error marshalling AP-REP for MechToken: %v", err)
		}
	case TOK_ID_KRB_ERROR:
		tb, err = m.KRBError.Marshal()
		if err != nil {
			err = fmt.Errorf("gssapi: error marshalling KRB-ERROR for MechToken: %v", err)
		}
	}
	if err != nil {
		return
	}
	b = append(b, tb...)

	outTok = asn1tools.AddASNAppTag(b, 0)
	return
}

// unmarshal a KRB5Token.
func (m *kRB5Token) unmarshal(b []byte) error {
	m.APReq = nil
	m.APRep = nil
	m.KRBError = nil

	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("gssapi: error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(OID()) {
		return fmt.Errorf("gssapi: error unmarshalling KRB5Token, OID is %s not %s", oid.String(), OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("gssapi: krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("gssapi: error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = &a
	case TOK_ID_KRB_AP_REP:
		var a aPRep
		err = a.unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("gssapi: error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = &a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("gssapi: error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = &a
	}
	return nil
}

// Create the GSSAPI checksum for the authenticator.  This isn't really
// a checksum, it is a way to carry GSSAPI level context infromation in
// the Kerberos AP-RREQ message. See RFC 4121 § 4.1.1
func newAuthenticatorChksum(flags gssapi.ContextFlag) []byte {
	// 24 octet minimum length, up to and including context-establishment flags
	a := make([]byte, 24)

	// 4-byte length of "channel binding" info, always 16 bytes
	binary.LittleEndian.PutUint32(a[:4], 16)

	// Octets 4..19: Channel binding info, left zero

	// Context-establishment flags
	binary.LittleEndian.PutUint32(a[20:24], uint32(flags))

	return a
}
