package gsscommon

import "time"

// GSSAPI Security-Context Management, RFC 2743 § 2.2

type SecContextInfo struct {
	PeerName  GssName
	Mech      GssMech
	Flags     ContextFlag
	ExpiresAt time.Time
}

type SecContext interface {
	Delete() ([]byte, error) // RFC 2743 § 2.2.3
}
