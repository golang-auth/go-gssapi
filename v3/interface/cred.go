package gsscommon

// GSSAPI Credential Management, RFC 2743 § 2.1

import "time"

type CredUsage int

const (
	CredUsageInitiateAndAccept CredUsage = iota
	CredUsageInitiateOnly
	CreUsageAcceptOnly
)

type InquireCredByMechResult struct {
	Name             string
	LifetimeInitiate time.Duration
	LifetimeAccept   time.Duration
	Usage            CredUsage
}

type Credential interface {
	// // Release can return nil, ErrNoCred or ErrFailure
	// Release() error

	// // Inquire can return nil, ErrNoCred, ErrDefectiveCredential, ErrCredentialsExpired or ErrFailure
	// Inquire(name string, lifetime time.Duration, mechs []Oid, usage CredUsage)

	// // Add can return nil, ErrDuplicateElement, ErrBadMech, ErrBadNameType, ErrBadName, ErrNoCred, ErrCredentialsExpired or ErrFailure
	// Add(name string, initiatorTime time.Duration, acceptorTime time.Duration, mech Oid, usage CredUsage) error

	// // InquireByMech can return nil, ErrNoCred, ErrDefectiveCredential, ErrCredentialsExpired, ErrBadMech, ErrFailure
	// InquireByMech(mech Oid) (*InquireCredByMechResult, error)

	// // in place of actual_mechs and lifetime_rec outputs from Gss_Acquite_cred (RFC2743 § 2.1.1)
	// Mech() Oid
	// TimeRemaining() time.Duration
}
