package krb5

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	gokrbgss "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	ianaflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/jake-scott/go-gssapi"
)

func init() {
	gssapi.Register("kerberos_v5", NewKrb5Mech)
}

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
	ourSequenceNumber   uint64
	theirSequenceNumber uint64
	theirSubKey         *types.EncryptionKey
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
	if m.isEstablished {
		f = m.sessionFlags
	}
	return
}

func (m *Krb5Mech) Initiate(serviceName string, requestFlags gssapi.ContextFlag) (tokenOut []byte, err error) {
	m.isEstablished = false
	m.waitingForMutual = false
	m.isInitiator = true

	// Obtain a Kerberos ticket for the service
	if err := m.krbInit(serviceName); err != nil {
		return nil, err
	}

	// Stash the subset of the request flags that we support
	m.sessionFlags = requestFlags & (gssapi.ContextFlagConf | gssapi.ContextFlagInteg |
		gssapi.ContextFlagMutual | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence)

	// Create a Kerberos AP-REQ message with GSSAPI checksum
	apreq, err := m.getAPReqMessage()
	if err != nil {
		return nil, err
	}

	// Create the GSSAPI token
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	gssToken := KRB5Token{
		OID:   OID(),
		tokID: tb,
		APReq: apreq,
	}

	tokenOut, err = gssToken.Marshal()
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// we need another round if we're doing mutual auth - we will receive an AP-REP from the server
	if m.sessionFlags&gssapi.ContextFlagMutual == 0 {
		m.isEstablished = true
	} else {
		err = gssapi.ContinueNeeded
		m.waitingForMutual = true
	}
	return
}

func (m *Krb5Mech) Continue(tokenIn []byte) (tokenOut []byte, err error) {
	if m.isEstablished {
		err = fmt.Errorf("gssapi: context already established, call Start to create a new context")
		return
	}

	if !m.waitingForMutual {
		err = fmt.Errorf("gssapi: context is not ready, call Start to initalize a new context")
		return
	}

	// unmarshal the GSSAPI token
	gssToken := KRB5Token{}
	if err = gssToken.Unmarshal(tokenIn); err != nil {
		return
	}

	// decrypt the private part of the AP-REP message
	plaintext, err := crypto.DecryptEncPart(gssToken.APRep.EncPart, *m.sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// unmarshal the plaintext encrypted-part
	msg := messages.EncAPRepPart{}
	if err = msg.Unmarshal(plaintext); err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// stash their sequence number and subkey for use in GSS Wrap
	m.theirSequenceNumber = uint64(msg.SequenceNumber)
	m.theirSubKey = &msg.Subkey

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
	return
}

func (m *Krb5Mech) Wrap(tokenIn []byte, confidentiality bool) (tokenOut []byte, err error) {
	wt, err := m.newWrapToken(tokenIn, confidentiality)
	if err != nil {
		return
	}

	tokenOut, err = wt.Marshal()
	return
}

func (m *Krb5Mech) Unwrap(tokenIn []byte) (tokenOut []byte, err error) {
	// Unmarshall the token
	wt := gokrbgss.WrapToken{}
	if err = wt.Unmarshal(tokenIn, m.isInitiator); err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// Verify the token's integrity
	// Checksum always uses the SEAL key usage
	if _, err = wt.Verify(m.unwrapKey(&wt), keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// Check the sequence number
	if wt.SndSeqNum != m.theirSequenceNumber {
		err = fmt.Errorf("gssapi: bad sequence number from peer, got %d, wanted %d", wt.SndSeqNum, m.theirSequenceNumber)
		return
	}
	m.theirSequenceNumber++

	if wt.Flags&2 == 2 {
		// Decrypt the message
		tokenOut, err = crypto.DecryptMessage(wt.Payload, m.unwrapKey(&wt), m.unwrapKeyUsage(&wt))
		if err != nil {
			err = fmt.Errorf("gssapi: %s", err)
			return
		}
	} else {
		tokenOut = wt.Payload
	}

	return
}

// return the sub-key from the AP-REP if the AcceptorSubkey flag is set
func (m *Krb5Mech) unwrapKey(wt *gokrbgss.WrapToken) types.EncryptionKey {
	if wt.Flags&4 == 4 {
		return *m.theirSubKey
	} else {
		return *m.sessionKey
	}
}

func (m *Krb5Mech) unwrapKeyUsage(wt *gokrbgss.WrapToken) uint32 {
	isSealed := wt.Flags&2 == 2
	switch {
	case m.isInitiator && isSealed:
		return keyusage.GSSAPI_ACCEPTOR_SEAL
	case m.isInitiator && !isSealed:
		return keyusage.GSSAPI_ACCEPTOR_SIGN
	case !m.isInitiator && isSealed:
		return keyusage.GSSAPI_INITIATOR_SEAL
	case !(m.isInitiator || isSealed):
		return keyusage.GSSAPI_INITIATOR_SIGN
	}

	return 0
}

func (m *Krb5Mech) getAPReqMessage() (apreq messages.APReq, err error) {
	auth, err := types.NewAuthenticator(m.krbClient.Credentials.Domain(), m.krbClient.Credentials.CName())
	if err != nil {
		err = fmt.Errorf("gssapi: generating new authenticator: %s", err)
		return
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  newAuthenticatorChksum(m.sessionFlags),
	}

	apreq, err = messages.NewAPReq(*m.ticket, *m.sessionKey, auth)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
		return
	}

	// set the Kerberos APREQ MUTUAL-REQUIRED option if we've been asked to perform mutual auth
	if m.sessionFlags&gssapi.ContextFlagMutual != 0 {
		types.SetFlag(&apreq.APOptions, ianaflags.APOptionMutualRequired)
	}

	// stash the sequence number for use in GSS Wrap
	m.ourSequenceNumber = uint64(auth.SeqNumber)

	// stash the APReq time flags for use in mutual authentication
	m.clientCTime = auth.CTime
	m.clientCusec = auth.Cusec

	return
}

func (m *Krb5Mech) krbInit(service string) (err error) {
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

func (m *Krb5Mech) newWrapToken(payload []byte, sealed bool) (tokenOut gokrbgss.WrapToken, err error) {
	// using the session key for now until we implement subkeys
	encType, err := crypto.GetEtype(m.sessionKey.KeyType)
	if err != nil {
		err = fmt.Errorf("gssapi: %s", err)
	}

	var flags byte
	if sealed {
		flags |= 2 // sealed
	}
	if !m.isInitiator {
		flags |= 1 // send by acceptor
	}

	tokenOut = gokrbgss.WrapToken{
		Flags: flags,
		// Checksum size: length of output of the HMAC function, in bytes.
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: m.ourSequenceNumber,
		Payload:   payload,
	}

	usage := keyusage.GSSAPI_INITIATOR_SEAL
	if !m.isInitiator {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	if err = tokenOut.SetCheckSum(*m.sessionKey, uint32(usage)); err != nil {
		err = fmt.Errorf("gssapi: ", err)
		return
	}

	m.ourSequenceNumber++ // only bump the sequence number if everything is good
	return
}
