// SPDX-License-Identifier: Apache-2.0

package gssapi

// GSSAPI Security-Context Management, RFC 2743 § 2.2

type SecContextInfo struct {
	InitiatorName    GssName
	AcceptorName     GssName
	Mech             GssMech
	Flags            ContextFlag
	ExpiresAt        GssLifetime
	LocallyInitiated bool
	FullyEstablished bool
	ProtectionReady  bool
	Transferrable    bool
}

type SecContext interface {
	Delete() ([]byte, error)                      // RFC 2743 § 2.2.3
	ProcessToken([]byte) error                    // RFC 2743 § 2.2.4
	ExpiresAt() (*GssLifetime, error)             // RFC 2743 § 2.2.5
	Inquire() (*SecContextInfo, error)            // RFC 2743 § 2.2.6
	WrapSizeLimit(bool, uint, QoP) (uint, error)  // RFC 2743 § 2.2.7
	Export() ([]byte, error)                      // RFC 2743 § 2.2.8
	GetMIC([]byte, QoP) ([]byte, error)           // RFC 2743 § 2.3.1
	VerifyMIC([]byte, []byte) (QoP, error)        // RFC 2743 § 2.3.2
	Wrap([]byte, bool, QoP) ([]byte, bool, error) // RFC 2743 § 2.3.3
	Unwrap([]byte) ([]byte, bool, QoP, error)     // RFC 2743 § 2.3.4

	ContinueNeeded() bool
	Continue([]byte) ([]byte, error)
}
