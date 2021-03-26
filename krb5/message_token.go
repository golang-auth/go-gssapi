package krb5

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"

	"github.com/jcmturner/gokrb5/v8/types"
)

/*
 * Derived from github.com/jcmturner/gokrb5/gssapi/wrapToken.go
 *
 * The modified version adds functionality for sealing GSSAPI messages
 *
 */

// RFC 4121 §  4.2.6
const (
	msgTokenHdrLen          = 16
	msgTokenFillerByte byte = 0xFF
)

// RFC 4121 §  4.2.2
type GSSMessageTokenFlag uint8

const (
	GSSMessageTokenFlagSentByAcceptor GSSMessageTokenFlag = 1 << iota
	GSSMessageTokenFlagSealed
	GSSMessageTokenFlagAcceptorSubkey
)

// RFC 4121 §  4.2.6.1
type MICToken struct {
	// 2 byte token ID (0x04, 0x04)
	Flags GSSMessageTokenFlag
	// 5 byte filler (0xFF)
	SequenceNumber uint64 // 64-bit sequence number
	Checksum       []byte
	signed         bool
}

// RFC 4121 §  4.2.6.2
type WrapToken struct {
	// 2 byte token ID (0x05, 0x04)
	Flags GSSMessageTokenFlag
	// 1 byte filler (0xFF)
	EC             uint16 // "Extra count" - the checksum or padding length
	RRC            uint16 // right rotation count for SSPI (we don't support this yet)
	SequenceNumber uint64 // 64-bit sequence number
	Payload        []byte // signed or encrypted payload
	signedOrSealed bool
}

// Return the 2 bytes identifying a GSS API Wrap token
func getGssWrapTokenId() [2]byte {
	return [2]byte{0x05, 0x04}
}

// Return the 2 bytes identifying a GSS API MIC token
func getGssMICTokenId() [2]byte {
	return [2]byte{0x04, 0x04}
}

// RFC 4121 §  4.2.4
// Checksum is calculated over the plaintext (supplied token payload), and
// the token header with EC and RRC set to zero
// The function modifies the Payload and EC/RRC fields of the WrapToken
func (wt *WrapToken) Sign(key types.EncryptionKey) error {
	if wt.Payload == nil {
		return errors.New("gssapi: attemp to sign token with no payload")
	}
	if wt.signedOrSealed {
		return errors.New("gssapi: attempt to sign a signed/sealed token")
	}

	sig, err := wt.computeChecksum(key)
	if err != nil {
		return fmt.Errorf("gssapi: %s", err)
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return fmt.Errorf("gssapi: %s", err)
	}

	wt.Payload = append(wt.Payload, sig...)
	wt.EC = uint16(encType.GetHMACBitLength() / 8)
	wt.RRC = 0
	wt.signedOrSealed = true

	return nil
}

// RFC 4121 §  4.2.4
// Encrypts the Payload and sets EC/RRC on the WrapToken
func (wt *WrapToken) Seal(key types.EncryptionKey) (err error) {
	if wt.Payload == nil {
		return errors.New("gssapi: attemp to encrypt token with no payload")
	}
	if wt.signedOrSealed {
		return errors.New("gssapi: attempt to seal a signed/sealed token")
	}

	toEncrypt := make([]byte, 0, len(wt.Payload)+msgTokenHdrLen)
	toEncrypt = append(toEncrypt, wt.Payload...)
	toEncrypt = append(toEncrypt, wt.header()...)

	usage := keyusage.GSSAPI_INITIATOR_SEAL
	if wt.Flags&GSSMessageTokenFlagSentByAcceptor != 0 {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}
	var encData []byte
	_, encData, err = encType.EncryptMessage(key.KeyValue, toEncrypt, uint32(usage))
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
	}

	wt.Payload = encData
	wt.EC = 0
	wt.RRC = 0
	wt.signedOrSealed = true

	return
}

func (wt *WrapToken) header() (hdr []byte) {
	hdr = make([]byte, msgTokenHdrLen)

	tokID := getGssWrapTokenId()
	hdr1 := []byte{
		tokID[0], tokID[1], // token ID
		byte(wt.Flags), // flags
		0xFF,           // filler
		0x00, 0x00,     // EC
		0x00, 0x00, // RRC
	}

	copy(hdr, hdr1)
	binary.BigEndian.PutUint64(hdr[8:], wt.SequenceNumber)

	return
}

func (wt *WrapToken) computeChecksum(key types.EncryptionKey) (cksum []byte, err error) {
	// wrap tokens always use the Seal key usage (RFC 4121 § 2)
	usage := keyusage.GSSAPI_INITIATOR_SEAL
	if wt.Flags&GSSMessageTokenFlagSentByAcceptor != 0 {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}

	plLen := len(wt.Payload)

	// Build a slice containing { payload | header }
	cksumData := make([]byte, 0, msgTokenHdrLen+plLen)
	cksumData = append(cksumData, wt.Payload...)
	cksumData = append(cksumData, wt.header()...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	cksum, err = encType.GetChecksumHash(key.KeyValue, cksumData, uint32(usage))
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	return
}

// Marshal a token that has already been signed or sealed
func (wt *WrapToken) Marshal() (token []byte, err error) {
	if !wt.signedOrSealed {
		err = errors.New("gssapi: wrap token is not signed or sealed")
		return
	}

	tokenID := getGssWrapTokenId()
	token = make([]byte, msgTokenHdrLen+len(wt.Payload))

	copy(token[0:], tokenID[:])
	token[2] = byte(wt.Flags)
	token[3] = msgTokenFillerByte
	binary.BigEndian.PutUint16(token[4:6], wt.EC)
	binary.BigEndian.PutUint16(token[6:8], wt.RRC)
	binary.BigEndian.PutUint64(token[8:16], wt.SequenceNumber)
	copy(token[16:], wt.Payload)

	return
}

// Unmarshal a signed or sealed token
func (wt *WrapToken) Unmarshal(token []byte) (err error) {
	// zero everything in the token
	*wt = WrapToken{}

	// token must be at least 16 bytes
	if len(token) < msgTokenHdrLen {
		return errors.New("gssapi: wrap token is too short")
	}

	// Check for 0x60 as the first byte;  As per RFC 4121 § 4.4, these Token IDs
	// are reserved - and indicate 'Generic GSS-API token framing' that was used by
	// GSS-API v1, and are not supported in GSS-API v2.. catch that specific case so
	// we can emmit a useful message
	if token[0] == 0x60 {
		return errors.New("gssapi: GSS-API v1 message tokens are not supported")
	}

	// check token ID
	tokenID := getGssWrapTokenId()
	if !bytes.Equal(tokenID[:], token[0:2]) {
		return errors.New("gssapi: bad wrap token ID")
	}

	wt.Flags = GSSMessageTokenFlag(token[2])

	if token[3] != msgTokenFillerByte {
		return errors.New("gssapi: invalid wrap token (bad filler)")
	}

	wt.EC = binary.BigEndian.Uint16(token[4:6])
	wt.RRC = binary.BigEndian.Uint16(token[6:8])
	wt.SequenceNumber = binary.BigEndian.Uint64(token[8:16])

	if len(token) > msgTokenHdrLen {
		wt.Payload = token[16:]
	}

	wt.signedOrSealed = true
	return nil
}

func (wt *WrapToken) VerifyAndDecode(key types.EncryptionKey, expectFromAcceptor bool) (isSealed bool, err error) {
	if !wt.signedOrSealed {
		return false, errors.New("gssapi: wrap token is not signed or sealed")
	}
	if wt.Payload == nil || len(wt.Payload) == 0 {
		return false, errors.New("gssapi: cannot verify an empty wrap token payload")
	}

	isFromAcceptor := wt.Flags&GSSMessageTokenFlagSentByAcceptor != 0
	if isFromAcceptor != expectFromAcceptor {
		return false, fmt.Errorf("gssapi: wrap token from acceptor: %t, expect from acceptor: %t", isFromAcceptor, expectFromAcceptor)
	}

	if wt.Flags&GSSMessageTokenFlagSealed != 0 {
		return true, wt.decrypt(key)
	} else {
		return false, wt.checkSig(key)
	}

	return
}

func (wt *WrapToken) decrypt(key types.EncryptionKey) (err error) {
	usage := keyusage.GSSAPI_INITIATOR_SEAL
	if wt.Flags&GSSMessageTokenFlagSentByAcceptor != 0 {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return fmt.Errorf("gssapi: wrap token: %s", err)
	}

	var decrypted []byte
	decrypted, err = encType.DecryptMessage(key.KeyValue, wt.Payload, uint32(usage))
	if err != nil {
		return fmt.Errorf("gssapi: wrap token: %s", err)
	}

	// check that the decrypted payload is big enough
	if len(decrypted) < int(wt.EC+msgTokenHdrLen) {
		return errors.New("gssapi: decrypted wrap token payload is too short")
	}

	// save the decrypted header part from the end of the plaintext
	decryptedHeader := decrypted[len(decrypted)-msgTokenHdrLen:]

	// check that plain text header wasn't modified
	wt2 := WrapToken{}
	if err = wt2.Unmarshal(decryptedHeader); err != nil {
		return
	}
	if !(wt.Flags == wt2.Flags &&
		wt.EC == wt2.EC &&
		wt.SequenceNumber == wt2.SequenceNumber) {
		return errors.New("gssapi: wrap token header was modified")
	}

	// remove the header and extra-count bytes from the decrypted payload
	wt.Payload = decrypted[0 : len(decrypted)-msgTokenHdrLen-int(wt.EC)]
	wt.signedOrSealed = false

	return
}

func (wt *WrapToken) checkSig(key types.EncryptionKey) (err error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return fmt.Errorf("gssapi: wrap token: %s", err)
	}

	// extra-count should be the crypto checksum length
	if wt.EC != uint16(encType.GetHMACBitLength()/8) {
		return errors.New("gssapi: bad wrap token checksum length")
	}

	// check that the payload is big enough
	if len(wt.Payload) < int(wt.EC) {
		return errors.New("gssapi: signed wrap token payload is too short")
	}

	tokCksum := wt.Payload[len(wt.Payload)-int(wt.EC):]

	wt2 := *wt
	wt2.Payload = wt.Payload[0 : len(wt.Payload)-int(wt.EC)]
	computedCksum, err := wt2.computeChecksum(key)
	if err != nil {
		return fmt.Errorf("gssapi: %s", err)
	}

	if !hmac.Equal(tokCksum, computedCksum) {
		return errors.New("gssapi: invalid wrap token checksum")
	}

	// remove the signature from the payload
	wt.Payload = wt.Payload[0 : len(wt.Payload)-int(wt.EC)]
	wt.signedOrSealed = false

	return
}

// Ported from MIT source code (gss_krb5int_rotate_left)
func rotateLeft(buf []byte, rc uint) (out []byte) {
	defer func() {
		out = buf
	}()

	if len(buf) == 0 || rc == 0 {
		return
	}

	rc = rc % uint(len(buf))
	if rc == 0 {
		return
	}

	tmpBuf := make([]byte, rc)
	copy(tmpBuf, buf[0:rc])
	copy(buf, buf[rc:])
	copy(buf[uint(len(buf))-rc:], tmpBuf)

	return
}

// RFC 4121 §  4.2.4
// Checksum is calculated over the plaintext (supplied token payload), and
// the token header
func (mt *MICToken) Sign(payload []byte, key types.EncryptionKey) (err error) {
	// mic tokens always use the Sign key usage
	usage := keyusage.GSSAPI_INITIATOR_SIGN
	if mt.Flags&GSSMessageTokenFlagSentByAcceptor != 0 {
		usage = keyusage.GSSAPI_ACCEPTOR_SIGN
	}

	cksumData := make([]byte, 0, msgTokenHdrLen+len(payload))
	cksumData = append(cksumData, payload...)
	cksumData = append(cksumData, mt.header()...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	mt.Checksum, err = encType.GetChecksumHash(key.KeyValue, cksumData, uint32(usage))
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	mt.signed = true

	return
}

func (mt *MICToken) header() (hdr []byte) {
	hdr = make([]byte, msgTokenHdrLen)

	tokID := getGssMICTokenId()
	hdr1 := []byte{
		tokID[0], tokID[1], // token ID
		byte(mt.Flags),               // flags
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // filler
		0x00, 0x00, // EC
		0x00, 0x00, // RRC
	}

	copy(hdr, hdr1)
	binary.BigEndian.PutUint64(hdr[8:], mt.SequenceNumber)

	return
}

func (mt *MICToken) Marshal() (token []byte, err error) {
	if !mt.signed {
		err = errors.New("gssapi: MIC token is not signed")
	}

	tokenID := getGssMICTokenId()
	token = make([]byte, msgTokenHdrLen+len(mt.Checksum))

	copy(token[0:], tokenID[:])
	token[2] = byte(mt.Flags)
	copy(token[3:8], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	binary.BigEndian.PutUint64(token[8:16], mt.SequenceNumber)
	copy(token[16:], mt.Checksum)

	return
}

func (mt *MICToken) Unmarshal(token []byte) (err error) {
	// zero out the MIC token
	*mt = MICToken{}

	// token must be at least 16 bytes
	if len(token) < msgTokenHdrLen {
		return errors.New("gssapi: wrap token is too short")
	}

	// Check for 0x60 as the first byte;  As per RFC 4121 § 4.4, these Token IDs
	// are reserved - and indicate 'Generic GSS-API token framing' that was used by
	// GSS-API v1, and are not supported in GSS-API v2.. catch that specific case so
	// we can emmit a useful message
	if token[0] == 0x60 {
		return errors.New("gssapi: GSS-API v1 message tokens are not supported")
	}

	// check token ID
	tokenID := getGssMICTokenId()
	if !bytes.Equal(tokenID[:], token[0:2]) {
		return errors.New("gssapi: bad MIC token ID")
	}

	mt.Flags = GSSMessageTokenFlag(token[2])

	if !bytes.Equal(token[3:8], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		return errors.New("gssapi: invalid MIC token (bad filler)")
	}

	mt.SequenceNumber = binary.BigEndian.Uint64(token[8:16])

	if len(token) > msgTokenHdrLen {
		mt.Checksum = token[16:]
	}

	mt.signed = true

	return
}

func (mt *MICToken) Verify(payload []byte, key types.EncryptionKey, expectFromAcceptor bool) (err error) {
	if !mt.signed {
		return errors.New("gssapi: MIC token is not signed")
	}

	if len(payload) == 0 {
		return errors.New("gssapi: cannot verify an empty MIC token payload")
	}

	isFromAcceptor := mt.Flags&GSSMessageTokenFlagSentByAcceptor != 0
	if isFromAcceptor != expectFromAcceptor {
		return fmt.Errorf("gssapi: MIC token from acceptor: %t, expect from acceptor: %t", isFromAcceptor, expectFromAcceptor)
	}

	// copy the token and use it to sign the supplied payload
	wt2 := *mt
	if err = wt2.Sign(payload, key); err != nil {
		return err
	}

	// check the token's checksums
	if !bytes.Equal(mt.Checksum, wt2.Checksum) {
		return errors.New("gssapi: invalid MIC token checksum")
	}

	return
}
