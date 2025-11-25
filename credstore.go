// SPDX-License-Identifier: Apache-2.0

package gssapi

// CredStoreOpt options are used to define the behaviour of the Credential Store extension methods.
// Provider implementations can supplement the options defined here with additional options.
type CredStoreOpt int

const (
	// CredStoreCCache is the name of the credential cache to use for aquiring initiator credentials
	// or the credential cache or collection where credentials will be stored.
	CredStoreCCache CredStoreOpt = 1 << iota
	// CredStoreClientKeytab is the name of the keytab to use when aquiring initiator credentials,
	// if necessary to refresh the credentials in the ccache.
	CredStoreClientKeytab
	// CredStoreServerKeytab is the name of the keytab to use for aquiring acceptor credentials and
	// for verification of initiator credentials acquired using a password and verified.
	CredStoreServerKeytab
	// Password can be used when acquiring fresh initiator credentials.  Cannot be used with CredStoreCCache
	// or CredStoreClientKeytab.  Credentials are acquired into into a unique memory credential cache.
	CredStorePassword
	// RCache defines the name of the replay cache to use when acquiring acceptor credentials.
	CredStoreRCache
	// Verify causes a ticket to be be obtained from the TGS when acquiring initiator credentials.
	// The ticket is validated using a service key from the keytab specified by CredStoreServerKeytab.
	// The value can be the name of a principal in the keytab or the empty string, which uses any
	// host service principal in the keytab.  The option can be used to validate that credentials
	// were obtained from a trusted KDC.
	CredStoreVerify
)

// CredStore defines a set of credential store extension options and their values.
type CredStore interface {
	SetOption(option int, value string) error
	GetOption(option int) (string, bool)
}

// CredStoreOption is a function type for configuring credential store options.
type CredStoreOption func(o CredStore) error

// WithCredStoreCCache configures the name of the credential cache to use for aquiring initiator credentials
func WithCredStoreCCache(cache string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStoreCCache), cache)
	}
}

// WithCredStoreClientKeytab configures the name of the keytab to use when aquiring initiator credentials,
// if necessary to refresh the credentials in the ccache.
func WithCredStoreClientKeytab(keytab string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStoreClientKeytab), keytab)
	}
}

// WithCredStoreServerKeytab configures the name of the keytab to use for aquiring acceptor credentials and
// for verification of initiator credentials acquired using a password and verified.
func WithCredStoreServerKeytab(keytab string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStoreServerKeytab), keytab)
	}
}

// WithCredStorePassword configures the password to use when acquiring fresh initiator credentials.
// Cannot be used with CredStoreCCache or CredStoreClientKeytab.
// Credentials are acquired into into a unique memory credential cache.
func WithCredStorePassword(password string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStorePassword), password)
	}
}

// WithCredStoreRCache configures the name of the replay cache to use when acquiring acceptor credentials.
func WithCredStoreRCache(rCache string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStoreRCache), rCache)
	}
}

// WithCredStoreVerify configures the ticket to be be obtained from the TGS when acquiring initiator credentials.
// The ticket is validated using a service key from the keytab specified by CredStoreServerKeytab.
// The value can be the name of a principal in the keytab or the empty string, which uses any host service principal in the keytab.
// The option can be used to validate that credentials were obtained from a trusted KDC.
func WithCredStoreVerify(principal string) CredStoreOption {
	return func(s CredStore) error {
		return s.SetOption(int(CredStoreVerify), principal)
	}
}

// ProviderExtCredStore extends the Provider interface with credential store extension functionality.
// Providers implementing this interface support acquiring and storing credentials from and to a
// credential store.  This interface is available if [provider.HasExtension(HasExtCredStore)] returns
// true.
type ProviderExtCredStore interface {
	Provider

	// AcquireCredentialFrom acquires a credential from the credential store or stores configured by opts
	//
	// Parameters:
	//   - name: the name of the principal to acquire credentials for
	//   - mechs: the mechanisms to acquire credentials for
	//   - usage: the desired credential usage
	//   - lifetime: the desired lifetime of the credentials
	//   - opts: optional credential store options
	//
	// Returns:
	//   - cred: the acquired credential
	//   - err: error if one occurred, otherwise nil
	AcquireCredentialFrom(name GssName, mechs []GssMech, usage CredUsage, lifetime *GssLifetime, opts ...CredStoreOption) (Credential, error)
}

// CredentialExtCredStore extends the Credential interface with credential store extension functionality.
// This interface is available if [provider.HasExtension(HasExtCredStore)] returns true.
type CredentialExtCredStore interface {
	Credential

	// StoreInto stores the credential into the credential store configured by opts
	// The overwrite and defaultCred parameters effect the semantics of storing the credential into
	// a credential cache collection.  An existing cache for the client principal in the collection
	// will be selected or a new one will be created.  If overwrite is false and the cache already exists
	// a ErrDuplicateElement will be returned.  If defaultCred is true, the primary cache of the collection
	// will be switched to the selected cache.
	//
	// Parameters:
	//   - mech: the mechanism to store
	//   - usage: the desired credential usage
	//   - overwrite: if true, the existing credential cache in a collection is overwritten, otherwise a ErrDuplicateElement will be returned
	//   - defaultCred: if true, the primary cache of the collection will be switched to the selected cache
	//   - opts: optional credential store options
	//
	// Returns:
	//   - numElmsStores: the number of elements stored
	//   - usageStored: the usage of the stored credential
	//   - err: error if one occurred, otherwise nil
	StoreInto(mech GssMech, usage CredUsage, overwrite bool, defaultCred bool, opts ...CredStoreOption) (mechsStored []GssMech, usageStored CredUsage, err error)

	AddFrom(name GssName, mech GssMech, usage CredUsage, initiatorLifetime *GssLifetime, acceptorLifetime *GssLifetime, mutate bool, opts ...CredStoreOption) (Credential, error)
}
