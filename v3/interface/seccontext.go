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
	ExpiresAt         *time.Time
	LocallyInitiated  bool
	FullyEstablished  bool
	ProtectionReady   bool
	Transferrable     bool
}

type SecContext interface {
	Delete() ([]byte, error)                    // RFC 2743 § 2.2.3
	ProcessToken([]byte) error                  // RFC 2743 § 2.2.4
	ExpiresAt() (time.Time, error)              // RFC 2743 § 2.2.5
	Inquire() (*SecContextInfo, error)          // RFC 2743 § 2.2.6
	WrapSizeLimit(bool, uint32) (uint32, error) // RFC 2743 § 2.2.7
	Export() ([]byte, error)                    // RFC 2743 § 2.2.8
	GetMIC([]byte) ([]byte, error)              // RFC 2743 § 2.3.1
	VerifyMIC([]byte, []byte) error             // RFC 2743 § 2.3.2
	Wrap([]byte, bool) ([]byte, bool, error)    // RFC 2743 § 2.3.3
	Unwrap([]byte) ([]byte, bool, error)        // RFC 2743 § 2.3.4

	ContinueNeeded() bool
	Continue([]byte) ([]byte, error)
}
