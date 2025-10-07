// SPDX-License-Identifier: Apache-2.0

package gssapi

// GSSAPI Credential Management, RFC 2743 § 2.1

// CredUsage defines the intended usage for credentials as specified in RFC 2743 § 2.1.1.
type CredUsage int

// Credential usage values as defined in RFC 2743 § 2.1.1
const (
	// CredUsageInitiateAndAccept indicates the credential may be used for both initiating and accepting contexts
	CredUsageInitiateAndAccept CredUsage = iota
	// CredUsageInitiateOnly indicates the credential may only be used for initiating contexts
	CredUsageInitiateOnly
	// CredUsageAcceptOnly indicates the credential may only be used for accepting contexts
	CredUsageAcceptOnly
)

// CredInfo contains information about a credential returned by Inquire and InquireByMech methods.
type CredInfo struct {
	Name            string      // String representation of the credential name
	NameType        GssNameType // Type of the credential name
	InitiatorExpiry GssLifetime // Expiry time for initiator credential elements
	AcceptorExpiry  GssLifetime // Expiry time for acceptor credential elements
	Usage           CredUsage   // Types of credentials held (accept, initiator, or both)
	Mechs           []GssMech   // Set of mechanisms supported by this credential
}

// Credential represents the CREDENTIAL HANDLE type from RFC 2743. This interface encompasses
// credential management functions as defined in RFC 2743 § 2.1.
//
// A credential may hold elements for one or more mechanisms, for use by either an acceptor
// or initiator. It may not hold multiple acceptor or initiator elements for the same mechanism.
type Credential interface {
	// Release releases the credential when it is no longer required.
	// This method corresponds to GSS_Release_cred from RFC 2743 § 2.1.2.
	//
	// Returns:
	//   - error if one occurred, otherwise nil
	Release() error // RFC 2743 § 2.1.2

	// Inquire returns information about the credential, implementing the GSS_Inquire_cred call
	// from RFC 2743 § 2.1.3.
	//
	// The `InitiatorExpiry` and `AcceptorExpiry` fields of `info` are only populated if the credential
	// contains initiator and acceptor credential elements, respectively. For multi-mechanism credentials,
	// the lifetimes represent the shortest lifetime of the elements in the credential.
	//
	// The Usage field represents the types of credentials (accept, initiator, or both) held.
	//
	// Use InquireByMech() for more fine-grained, mechanism-specific information.
	//
	// Returns:
	//   - info: information about the credential
	//   - err: error if one occurred, otherwise nil
	Inquire() (info *CredInfo, err error) // RFC 2743 § 2.1.3

	// Add adds a credential element to the Credential. This method implements the GSS_Add_cred call
	// described in RFC 2743 § 2.1.4.
	//
	// The RFC describes a mode where a new credential handle can be returned instead of modifying the
	// existing handle. The Go bindings define the addition of credentials to the existing Credential only.
	//
	// The RFC details a set of outputs related to the added credential. These are not returned by the Go
	// bindings; callers should use Inquire() or InquireByMech() instead.
	//
	// Parameters:
	//   - name: the name to add, or nil to add a credential that will trigger a request for a default
	//     name by InitSecContext
	//   - mech: the mechanism to add
	//   - usage: the desired credential usage
	//   - initiatorLifetime: the desired lifetime of the initiator credential if usage is
	//     CredUsageInitiateOnly or CredUsageInitiateAndAccept, or nil for a default value
	//   - acceptorLifetime: the desired lifetime of the acceptor credential if usage is
	//     CredUsageAcceptOnly or CredUsageInitiateAndAccept, or nil for a default value
	//
	// Returns:
	//   - error if one occurred, otherwise nil
	Add(name GssName, mech GssMech, usage CredUsage, initiatorLifetime *GssLifetime, acceptorLifetime *GssLifetime) error // RFC 2743 § 2.1.4

	// InquireByMech returns information about the credential element related to mech, implementing the
	// GSS_Inquire_cred_by_mech call from RFC 2743 § 2.1.5. This call is a finer-grained,
	// mechanism-specific version of Inquire.
	//
	// The InitiatorExpiry and AcceptorExpiry fields are only populated if the credential element may
	// be used by an initiator or acceptor, respectively. A nil value represents unsupported or
	// indefinite lifetime, and the zero time value represents an expired credential.
	//
	// The Usage field represents the types of credential elements (accept, initiator, or both) held for
	// the mech.
	//
	// Parameters:
	//   - mech: the mechanism to query
	//
	// Returns:
	//   - info: information about the credential element
	//   - err: error if one occurred, otherwise nil
	InquireByMech(mech GssMech) (info *CredInfo, err error) // RFC 2743 § 2.1.5
}

// CredentialExtRFC4178  extends the Credential interface to support the APIs defined in RFC 4178: GSSAPI Negotiation mechanism.
type CredentialExtRFC4178 interface {
	Credential
	SetNegotiationMechs([]GssMech) error     // RFC 4178 § B.1
	GetNegotiationMechs() ([]GssMech, error) // RFC 4178 § B.2
}

// CredentialExtRFC5588 extends the Credential interface to support the APIs defined in RFC 5588: GSSAPI Negotiation mechanismStoring delegated credentials.
type CredentialExtRFC5588 interface {
	Credential
	StoreCredential(usage CredUsage, mech GssMech, overwrite bool, makeDefault bool) ([]GssMech, CredUsage, error) // RFC 5588 § B.1
}

// CredentialExtGGF extends the Credential interface to support the APIs defined in GFD.24: GGF extensions.
type CredentialExtGGF interface {
	Credential
	Export() ([]byte, error)                         // GFD.24 § 2.1.1
	InquireByOid(oid Oid) (data [][]byte, err error) // GFD.24 § 2.3.2

}

// CredentialExtS4U extends the Credential interface to support the APIs defined in S4U extensions.
type CredentialExtS4U interface {
	Credential
	AquireImpersonateName(name GssName, mechs []GssMech, usage CredUsage, lifetime GssLifetime) (Credential, error)
	AddImpersonateName(impersonateCred Credential, name GssName, mech GssMech, usage CredUsage, initiatorLifetime GssLifetime, acceptorLifetime GssLifetime) (Credential, error)
}

// Acquire credentials with password extension
type CredentialExtCredPassword interface {
	Credential
	AddWithPassword(name GssName, password string, mech GssMech, usage CredUsage, initiatorLifetime GssLifetime, acceptorLifetime GssLifetime) (Credential, error)
}
