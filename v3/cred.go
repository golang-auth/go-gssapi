// SPDX-License-Identifier: Apache-2.0

package gssapi

// GSSAPI Credential Management, RFC 2743 § 2.1

import "time"

type CredUsage int

// Cred usage values as defined at RFC 2743 § 2.1.1
const (
	CredUsageInitiateAndAccept CredUsage = iota
	CredUsageInitiateOnly
	CredUsageAcceptOnly
)

type CredInfo struct {
	Name            string
	NameType        GssNameType
	InitiatorExpiry GssLifetime
	AcceptorExpiry  GssLifetime
	Usage           CredUsage
	Mechs           []GssMech
}

type Credential interface {
	Release() error                                                                                                         // RFC 2743 § 2.1.2
	Inquire() (*CredInfo, error)                                                                                            // RFC 2743 § 2.1.3
	Add(name GssName, mech GssMech, usage CredUsage, initiatorLifetime time.Duration, acceptorLifetime time.Duration) error // RFC 2743 § 2.1.4
	InquireByMech(mech GssMech) (*CredInfo, error)                                                                          // RFC 2743 § 2.1.5
}
