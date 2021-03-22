package krb5

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	ianaerrcode "github.com/jcmturner/gokrb5/v8/iana/errorcode"
	ianaflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/jake-scott/go-gssapi"
)

func init() {
	gssapi.Register("kerberos_v5", NewKrb5Mech)
}

var clockSkew = time.Second * 10

type acceptorISN int

const (
	DefaultAcceptorISNInitiator acceptorISN = iota
	DefaultAcceptorISNZero
)

// default acceptor initial sequence number: use the initiator's ISN if there is no mutual auth
var AcceptorISN acceptorISN = DefaultAcceptorISNInitiator

type Krb5Mech struct {
	krbClient           *client.Client
	isInitiator         bool
	isEstablished       bool
	waitingForMutual    bool
	service             string
	ticket              *messages.Ticket
	sessionKey          *types.EncryptionKey
	clientCTime         time.Time
	clientCusec         int
	sessionFlags        gssapi.ContextFlag
	requestFlags        gssapi.ContextFlag
	ourSequenceNumber   uint64
	theirSequenceNumber uint64
	initiatorSubKey     *types.EncryptionKey
	acceptorSubKey      *types.EncryptionKey
	peerName            string
}

func NewKrb5Mech() gssapi.Mech {
	return &Krb5Mech{}
}

func OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
}

func (m Krb5Mech) IsEstablished() bool {
	return m.isEstablished
}

func (m Krb5Mech) ContextFlags() (f gssapi.ContextFlag) {
	return m.sessionFlags
}

// RFC 4121 § 4.1
func (m *Krb5Mech) Accept(serviceName string) (err error) {
	m.isEstablished = false
	m.waitingForMutual = false
	m.isInitiator = false
	m.service = serviceName

	// Stash the subset of the request flags that we can support, except mutual
	// which we won't know about until we receive a token
	m.sessionFlags = gssapi.ContextFlagConf | gssapi.ContextFlagInteg |
		gssapi.ContextFlagReplay | gssapi.ContextFlagSequence

	return
}

func (m *Krb5Mech) Initiate(serviceName string, requestFlags gssapi.ContextFlag) (err error) {
	m.isEstablished = false
	m.waitingForMutual = false
	m.isInitiator = true

	// Obtain a Kerberos ticket for the service
	if err = m.krbClientInit(serviceName); err != nil {
		return
	}

	// Stash the subset of the request flags that we can support minus mutual until that completes
	m.sessionFlags = gssapi.ContextFlagConf | gssapi.ContextFlagInteg |
		gssapi.ContextFlagReplay | gssapi.ContextFlagSequence

	m.requestFlags = requestFlags & (gssapi.ContextFlagConf | gssapi.ContextFlagInteg |
		gssapi.ContextFlagMutual | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence)

	return
}

func (m *Krb5Mech) Continue(tokenIn []byte) (tokenOut []byte, err error) {
	if m.isEstablished {
		err = nil
		return
	}

	if m.isInitiator {
		return m.continueInitiator(tokenIn)
	} else {
		return m.continueAcceptor(tokenIn)
	}

	return
}

func (m *Krb5Mech) continueInitiator(tokenIn []byte) (tokenOut []byte, err error) {
	// first time, create the first context-establishment token
	//
	if tokenIn == nil || len(tokenIn) == 0 {
		// Create a Kerberos AP-REQ message with GSSAPI checksum
		var apreq messages.APReq
		apreq, err = m.getAPReqMessage()
		if err != nil {
			return
		}

		// Create the GSSAPI token
		tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
		gssToken := kRB5Token{
			OID:   OID(),
			tokID: tb,
			APReq: &apreq,
		}

		tokenOut, err = gssToken.marshal()
		if err != nil {
			err = fmt.Errorf("gssapi: %s", err)
			return
		}

		// we need another round if we're doing mutual auth - we will receive an AP-REP from the server
		if m.requestFlags&gssapi.ContextFlagMutual == 0 {
			m.isEstablished = true
		} else {
			m.waitingForMutual = true
		}

		return
	}

	// called again due to a previous ContinueNeeded result ?..
	if !m.waitingForMutual {
		err = fmt.Errorf("gssapi: context is not ready, call Start to initalize a new context")
		return
	}

	// unmarshal the GSSAPI token
	gssToken := kRB5Token{}
	if err = gssToken.unmarshal(tokenIn); err != nil {
		return
	}

	if gssToken.KRBError != nil {
		err = fmt.Errorf("gssapi: %s", gssToken.KRBError.Error())
		return
	}

	if gssToken.APRep == nil {
		err = errors.New("gssapi: GSSAPI token does not contain AP-REP message")
		return
	}

	// decrypt/verify the private part of the AP-REP message
	msg, err := gssToken.APRep.decryptEncPart(*m.sessionKey)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// stash their sequence number and subkey for use in GSS Wrap/Unwrap
	m.theirSequenceNumber = uint64(msg.SequenceNumber)
	if msg.Subkey.KeyType != 0 {
		m.acceptorSubKey = &msg.Subkey
	}

	// check the response has the same time values as the request
	// Note - we can't use time.Equal() as m.clientCTime has a monotomic clock value and
	// which causes the equality to fail
	if !(msg.CTime.Unix() == m.clientCTime.Unix() && msg.Cusec == m.clientCusec) {
		err = fmt.Errorf("gssapi: mutual authentication failed")
		return
	}

	// we're done!
	m.isEstablished = true
	m.waitingForMutual = false
	m.sessionFlags |= gssapi.ContextFlagMutual

	return

}

func (m *Krb5Mech) continueAcceptor(tokenIn []byte) (tokenOut []byte, err error) {
	// try to unmarshal the token
	gssInToken := kRB5Token{}
	if err = gssInToken.unmarshal(tokenIn); err != nil {
		return
	}

	if gssInToken.KRBError != nil {
		err = fmt.Errorf("gssapi: %s", gssInToken.KRBError.Error())
		return
	}

	// RFC says: must return a KRBError message to the client if the token ID was invalid
	// Note sure other implementatios really do this
	if gssInToken.KRBError == nil && gssInToken.APReq == nil && gssInToken.APRep == nil {
		tokenOut, err = mkGssErrKrbCode(ianaerrcode.KRB_AP_ERR_MSG_TYPE, "gss accept failed")
		return
	}

	// avoid crash if GSSAPI token isn't an initial token
	if gssInToken.APReq == nil {
		err = errors.New("gssapi: GSSAPI token does not contain AP-REQ message")
		return
	}

	ktFile := krbKtFile()

	err, krbErr := verifyAPReq(ktFile, gssInToken.APReq, clockSkew)
	if err != nil {
		tokenOut, err = mkGssErrFromKrbErr(krbErr.(messages.KRBError))
		return
	}

	// stash the sequence number for use in GSS Wrap
	m.theirSequenceNumber = uint64(gssInToken.APReq.Authenticator.SeqNumber)

	// stash the APReq time flags for use in mutual authentication
	m.clientCTime = gssInToken.APReq.Authenticator.CTime
	m.clientCusec = gssInToken.APReq.Authenticator.Cusec

	// stash the session key and ticket
	m.ticket = &gssInToken.APReq.Ticket
	m.sessionKey = &gssInToken.APReq.Ticket.DecryptedEncPart.Key

	// stash the initiator subkey if there is one
	if gssInToken.APReq.Authenticator.SubKey.KeyType != 0 {
		m.initiatorSubKey = &gssInToken.APReq.Authenticator.SubKey
	}

	// stash the client's principal name
	m.peerName = fmt.Sprintf("%s@%s",
		gssInToken.APReq.Ticket.DecryptedEncPart.CName.PrincipalNameString(),
		gssInToken.APReq.Ticket.DecryptedEncPart.CRealm)

	// if the client requested mutual authentication, send them an AP-REP message
	if types.IsFlagSet(&gssInToken.APReq.APOptions, ianaflags.APOptionMutualRequired) {
		tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REP)
		gssOutToken := kRB5Token{
			OID:   OID(),
			tokID: tb,
		}

		var aprep aPRep
		aprep, err = m.getAPRepMessage()
		if err != nil {
			return
		}
		gssOutToken.APRep = &aprep

		tokenOut, err = gssOutToken.marshal()
		if err != nil {
			return
		}

		m.sessionFlags |= gssapi.ContextFlagMutual

	} else {
		// if there is no mutual auth, we can't tell the client what our initial sequence number is
		// MIT and Microsoft use the client's ISN so let's do that, unless we're in Heimdal mode
		// see https://bugs.openjdk.java.net/browse/JDK-8201814
		switch AcceptorISN {
		case DefaultAcceptorISNInitiator:
			m.ourSequenceNumber = m.theirSequenceNumber
		case DefaultAcceptorISNZero:
			m.ourSequenceNumber = 0
		default:
			err = fmt.Errorf("gssapi: unknown acceptor-initial-sequence-number policy configured")
			return
		}

	}

	// we're done from an acceptor perspective
	m.isEstablished = true
	return
}

func (m *Krb5Mech) PeerName() string {
	return m.peerName
}

func (m *Krb5Mech) Wrap(tokenIn []byte, confidentiality bool) (tokenOut []byte, err error) {
	wt, err := m.newWrapToken(tokenIn, confidentiality)
	if err != nil {
		return
	}

	tokenOut, err = wt.Marshal()
	return
}

func (m *Krb5Mech) Unwrap(tokenIn []byte) (tokenOut []byte, isSealed bool, err error) {
	// Unmarshall the token
	wt := WrapToken{}
	if err = wt.Unmarshal(tokenIn); err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	var key types.EncryptionKey
	switch {
	case wt.Flags&GSSMessageTokenFlagAcceptorSubkey != 0:
		if m.acceptorSubKey == nil {
			err = errors.New("gssapi: acceptor subkey not negotiated during token unwrap")
			return
		}

		key = *m.acceptorSubKey
	case m.initiatorSubKey != nil:
		key = *m.initiatorSubKey
	default:
		key = *m.sessionKey
	}

	// Verify the token's integrity and get the unsealed / unsigned payload
	if isSealed, err = wt.VerifyAndDecode(key, m.isInitiator); err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// Check the sequence number
	if wt.SequenceNumber != m.theirSequenceNumber {
		err = fmt.Errorf("gssapi: bad sequence number from peer, got %d, wanted %d", wt.SequenceNumber, m.theirSequenceNumber)
		return
	}
	m.theirSequenceNumber++

	tokenOut = wt.Payload
	return
}

func (m *Krb5Mech) getAPReqMessage() (apreq messages.APReq, err error) {
	auth, err := types.NewAuthenticator(m.krbClient.Credentials.Domain(), m.krbClient.Credentials.CName())
	if err != nil {
		err = fmt.Errorf("gssapi: generating new authenticator: %s", err)
		return
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  newAuthenticatorChksum(m.requestFlags),
	}

	apreq, err = messages.NewAPReq(*m.ticket, *m.sessionKey, auth)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// set the Kerberos APREQ MUTUAL-REQUIRED option if we've been asked to perform mutual auth
	if m.requestFlags&gssapi.ContextFlagMutual != 0 {
		types.SetFlag(&apreq.APOptions, ianaflags.APOptionMutualRequired)
	}

	// stash the sequence number for use in GSS Wrap
	m.ourSequenceNumber = uint64(auth.SeqNumber)

	// stash the APReq time flags for use in mutual authentication
	m.clientCTime = auth.CTime
	m.clientCusec = auth.Cusec

	return
}

func (m *Krb5Mech) getAPRepMessage() (aprep aPRep, err error) {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return
	}

	encPart := encAPRepPart{
		CTime:          m.clientCTime, // copied from the APReq
		Cusec:          m.clientCusec,
		SequenceNumber: seq.Int64(),
	}

	aprep, err = newAPRep(*m.ticket, *m.sessionKey, encPart)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	m.ourSequenceNumber = uint64(encPart.SequenceNumber)
	return
}

func (m *Krb5Mech) krbClientInit(service string) (err error) {
	cfgFile := krbConfFile()
	ccFile := krbCCFile()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("gssapi: loading krb5.conf: %w", err)
	}

	ccache, err := credentials.LoadCCache(ccFile)
	if err != nil {
		return fmt.Errorf("gssapi: loading credentials cache: %w", err)
	}

	m.krbClient, err = client.NewFromCCache(ccache, cfg)
	if err != nil {
		return fmt.Errorf("gssapi: creating krb5 client: %w", err)
	}

	if err := m.krbClient.AffirmLogin(); err != nil {
		return fmt.Errorf("gssapi: checking TGT: %s", err)
	}

	tkt, key, err := m.krbClient.GetServiceTicket(service)
	if err != nil {
		return fmt.Errorf("gssapi: getting service ticket for '%s': %s", m.service, err)
	}
	m.ticket, m.sessionKey, m.service = &tkt, &key, service
	m.peerName = fmt.Sprintf("%s@%s", tkt.SName.PrincipalNameString(), tkt.Realm)

	return nil

}

func krbConfFile() string {
	cfgFile, ok := os.LookupEnv("KRB5_CONFIG")
	if !ok {
		cfgFile = "/etc/krb5.conf"
	}

	return cfgFile
}

func krbCCFile() string {
	ccFile, ok := os.LookupEnv("KRB5CCNAME")
	if !ok {
		ccFile = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
	}

	return strings.TrimPrefix(ccFile, "FILE:")
}

func krbKtFile() string {
	ktFile, ok := os.LookupEnv("KRB5_KTNAME")
	if !ok {
		ktFile = fmt.Sprintf("/var/kerberos/krb5/user/%d/client.keytab", os.Getuid())
	}

	return strings.TrimPrefix(ktFile, "FILE:")
}

func (m *Krb5Mech) newWrapToken(payload []byte, sealed bool) (token WrapToken, err error) {
	var flags GSSMessageTokenFlag

	if !m.isInitiator {
		flags |= GSSMessageTokenFlagSentByAcceptor // send by acceptor
	}
	if sealed {
		flags |= GSSMessageTokenFlagSealed // sealed
	}

	// use the acceptor subkey if it was negotiated during auth
	key := m.sessionKey
	if m.acceptorSubKey != nil {
		key = m.acceptorSubKey
		flags |= GSSMessageTokenFlagAcceptorSubkey
	}

	token = WrapToken{
		Flags:          flags,
		SequenceNumber: m.ourSequenceNumber,
		Payload:        payload,
	}

	// encrypt or sign the payload, see RFC 4121 § 4.2.4
	if sealed {
		err = token.Seal(*key)
	} else {
		err = token.Sign(*key)
	}

	if err == nil {
		m.ourSequenceNumber++ // only bump the sequence number if everything is good
	}

	return
}

// must return useful Kerberos error codes here so we can respond appropriately to the client if necessary
// err is also returned for local use (eg. logging an I/O error etc)
//
// This validation routine does *NOT* currently check addresses;  the gokrb5 version in messages/APReq doesn't
// do this properly and in any case this behaviour should depend on the local kerberos configuration
func verifyAPReq(ktFile string, apreq *messages.APReq, skew time.Duration) (err error, krbError error) {
	kt, err := keytab.Load(ktFile)
	if err != nil {
		krbError = messages.NewKRBError(apreq.Ticket.SName, apreq.Ticket.Realm, ianaerrcode.KRB_AP_ERR_NOKEY, "no key for service")
		return
	}

	err = apreq.Ticket.DecryptEncPart(kt, &apreq.Ticket.SName)
	if err != nil {
		if _, ok := err.(messages.KRBError); ok {
			krbError = err
			return
		} else {
			krbError = messages.NewKRBError(apreq.Ticket.SName, apreq.Ticket.Realm, ianaerrcode.KRB_AP_ERR_BAD_INTEGRITY, "could not decrypt ticket")
			return
		}
	}

	// Check time validity of ticket
	ok, err := apreq.Ticket.Valid(skew)
	if err != nil || !ok {
		krbError = err
		return
	}

	// Decrypt authenticator with session key from ticket's encrypted part
	err = apreq.DecryptAuthenticator(apreq.Ticket.DecryptedEncPart.Key)
	if err != nil {
		krbError = messages.NewKRBError(apreq.Ticket.SName, apreq.Ticket.Realm, errorcode.KRB_AP_ERR_BAD_INTEGRITY, "could not decrypt authenticator")
		return
	}

	// Check CName in authenticator is the same as that in the ticket
	if !apreq.Authenticator.CName.Equal(apreq.Ticket.DecryptedEncPart.CName) {
		krbError = messages.NewKRBError(apreq.Ticket.SName, apreq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CName in Authenticator does not match that in service ticket")
		return
	}

	// Check the clock skew between the client and the service server
	ct := apreq.Authenticator.CTime.Add(time.Duration(apreq.Authenticator.Cusec) * time.Microsecond)
	t := time.Now().UTC()
	if t.Sub(ct) > skew || ct.Sub(t) > skew {
		krbError = messages.NewKRBError(apreq.Ticket.SName, apreq.Ticket.Realm, errorcode.KRB_AP_ERR_SKEW, fmt.Sprintf("clock skew with client too large. greater than %v seconds", skew))
		return
	}

	return
}

func mkGssErrKrbCode(code int32, message string) (token []byte, err error) {
	ke := messages.NewKRBError(types.PrincipalName{}, "", code, message)
	return mkGssErrFromKrbErr(ke)
}

func mkGssErrFromKrbErr(ke messages.KRBError) (token []byte, err error) {
	tb, _ := hex.DecodeString(TOK_ID_KRB_ERROR)
	gssToken := kRB5Token{
		OID:      OID(),
		tokID:    tb,
		KRBError: &ke,
	}

	token, err = gssToken.marshal()
	if err == nil {
		// marshaled ok, return the kerberos error and token to the peer
		err = ke
	} else {
		// marshal failed, return that error and no token to send to the peer
		token = nil
	}

	return
}
