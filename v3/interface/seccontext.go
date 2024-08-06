package gsscommon

import "time"

// GSSAPI Security-Context Management, RFC 2743 § 2.2

type SecContextInfo struct {
	InitiatorName     string
	InitiatorNameType GssNameType
	AcceptorName      string
	AcceptorNameType  GssNameType
	Mech              GssMech
	Flags             ContextFlag
	ExpiresAt         time.Time
	LocallyInitiated  bool
	FullyEstablished  bool
	ProtectionReady   bool
	Transferrable     bool
}

type SecContext interface {
	Delete() ([]byte, error)           // RFC 2743 § 2.2.3
	Inquire() (*SecContextInfo, error) // RFC 2743§ 2.2.6

	ContinueNeeded() bool
}
