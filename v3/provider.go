// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"errors"
	"sync"
	"time"
)

var ErrProviderNotFound = errors.New("provider not found")

var registry struct {
	sync.Mutex
	libs map[string]ProviderConstructor
}

func init() {
	registry.libs = make(map[string]ProviderConstructor)
}

// ProviderConstructor defines the function signature passed to RegisterProvider, used
// by the registration interface to create new instances of a provider.
type ProviderConstructor func() (Provider, error)

// RegisterProvider associates the supplied provider factory with the unique
// name for the provider. If a provider with name is already registered, the new
// factory function will replace the existing registration.
//
// GSSAPI providers must register themselves by calling RegisterProvider in their
// init() function. Providers should document the unique name used in their call
// to RegisterProvider.
//
// Parameters:
//   - name: unique name (identifier) of the provider. The author should document this
//     identifier for consumption by users of the provider.
//   - f: function that can be used to instantiate the provider
//
// The function always succeeds.
func RegisterProvider(name string, f ProviderConstructor) {
	registry.Lock()
	defer registry.Unlock()

	registry.libs[name] = f
}

// NewProvider is used to instantiate a provider given its unique name. It does this by calling
// the provider factory function registered against the name. The function panics if name is
// not registered.
//
// This unique name is then used by consumer code to instantiate the desired GSSAPI implementation
// using the NewProvider method.
//
// Parameters:
//   - name: unique name of a previously registered provider
//
// Returns:
//   - p: provider instance
//   - err: error if one occurred, otherwise nil
func NewProvider(name string) (p Provider, err error) {
	registry.Lock()
	defer registry.Unlock()

	f, ok := registry.libs[name]
	if !ok {
		return nil, ErrProviderNotFound
	}

	return f()
}

// MustNewProvider wraps NewProvider in a panic.
//
// Parameters:
//   - name: unique name of a previously registered provider
//
// Returns:
//   - provider instance
//
// Panics if the provider name is not registeredor its constructor returns an error.
func MustNewProvider(name string) Provider {
	registry.Lock()
	defer registry.Unlock()

	f, ok := registry.libs[name]
	if !ok {
		panic("GSSAPI library not found: " + name)
	}

	p, err := f()
	if err != nil {
		panic(err)
	}

	return p
}

// QoP represents quality of protection values used in various security context operations
// like GetMIC, VerifyMIC, Wrap, Unwrap, and WrapSizeLimit. A zero value represents the
// default quality of protection.
type QoP uint

// InitSecContextOptions holds the optional parameters for initializing a security context.
// These options correspond to the optional parameters of GSS_Init_sec_context from RFC 2743 § 2.2.1.
type InitSecContextOptions struct {
	Credential     Credential      // Source credential for context establishment
	Mech           GssMech         // Specific mechanism to use
	Flags          ContextFlag     // Requested protection flags
	Lifetime       time.Duration   // Desired context lifetime
	ChannelBinding *ChannelBinding // Channel binding information
}

// InitSecContextOption is a function type for configuring InitSecContext options.
type InitSecContextOption func(o *InitSecContextOptions)

// WithInitiatorCredential supports the use of a source credential when initiating a security context,
// corresponding to the claimant_cred_handle parameter to GSS_Init_sec_context from the RFC.
func WithInitiatorCredential(cred Credential) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Credential = cred
	}
}

// WithInitiatorMech supports the use of a specific mechanism when establishing the context,
// corresponding to the mech_type parameter to GSS_Init_sec_context from the RFC.
func WithInitiatorMech(mech GssMech) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Mech = mech
	}
}

// WithInitiatorFlags allows the caller to control the requested protection flags when establishing
// a security context, corresponding to the *_req_flag parameters of GSS_Init_sec_context from the RFC.
func WithInitiatorFlags(flags ContextFlag) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Flags = flags
	}
}

// WithInitiatorLifetime supports the use of a non-default context lifetime, corresponding to
// the lifetime_req parameter of GSS_Init_sec_context from the RFC.
func WithInitiatorLifetime(life time.Duration) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Lifetime = life
	}
}

// WithChannelBinding supports the use of channel binding information when establishing the context,
// corresponding to the input_chan_bindings parameter of GSS_Init_sec_context from the RFC.
func WithInitiatorChannelBinding(cb *ChannelBinding) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.ChannelBinding = cb
	}
}

// AcceptSecContextOptions holds the optional parameters for accepting a security context.
// These options correspond to the optional parameters of GSS_Accept_sec_context from RFC 2743 § 2.2.2.
type AcceptSecContextOptions struct {
	Credential     Credential      // Acceptor credential for context establishment
	ChannelBinding *ChannelBinding // Channel binding information
}

// AcceptSecContextOption is a function type for configuring AcceptSecContext options.
type AcceptSecContextOption func(o *AcceptSecContextOptions)

// WithAcceptorCredential supports the use of a specifc credential when accepting a security context,
// corresponding to the acceptor_cred_handle parameter to GSS_Accept_sec_context from the RFC.
func WithAcceptorCredential(cred Credential) AcceptSecContextOption {
	return func(o *AcceptSecContextOptions) {
		o.Credential = cred
	}
}

// WithAcceptorChannelBinding supports the use of channel binding information when accepting a security context,
// corresponding to the chan_bindings parameter to GSS_Accept_sec_context from the RFC.
func WithAcceptorChannelBinding(cb *ChannelBinding) AcceptSecContextOption {
	return func(o *AcceptSecContextOptions) {
		o.ChannelBinding = cb
	}
}

// Provider is the interface that defines the top level GSSAPI functions that
// create name, credential and security contexts
type Provider interface {
	// Name returns the unique name of the provider.
	Name() string

	// ImportName corresponds to the GSS_Import_name function from RFC 2743 § 2.4.5.
	// Parameters:
	//   name:     A name-type specific octet-string
	//   nameType: One of the supported [GssNameType] constants
	// Returns:
	//   A GSSAPI Internal Name (IN) that should be freed using GssName.Release()
	ImportName(name string, nameType GssNameType) (GssName, error) // RFC 2743 § 2.4.5

	// AcquireCredential corresponds to the GSS_Acquire_cred function from RFC 2743 § 2.1.1.
	// Parameters:
	//   name:     A GSSAPI Internal Name, or nil to use the default.
	//   mechs:    A set of [GssMech] constants, or nil for the system default.
	//   usage:    Intended credential usage: initiate only, accept only, or both.
	//   lifetime: Desired credential lifetime duration, or zero (0) for the default.
	// Returns:
	//   A GSSAPI credential suitable for InitSecContext or AcceptSecContext, based on the usage.
	AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime *GssLifetime) (Credential, error) // RFC 2743 § 2.1.1

	// InitSecContext corresponds to the GSS_Init_sec_context function from RFC 2743 § 2.2.1.
	// Parameters:
	//   name: The GSSAPI Internal Name of the target.
	//   opts: Optional context establishment parameters, see [InitSecContextOption].
	// Returns:
	//   A uninitialized GSSAPI security context ready for exchanging tokens with the peer when
	//   the first call to [Continue()] with an empty input token is made.  [ContinueNeeded()] will true
	//   when this call returns successfully.
	InitSecContext(name GssName, opts ...InitSecContextOption) (SecContext, error) // RFC 2743 § 2.2.1

	// AcceptSecContext corresponds to the GSS_Accept_sec_context function from RFC 2743 § 2.2.2.
	// Parameters:
	//   opts: Optional context establishment parameters, see [AcceptSecContextOption].
	// Returns:
	//   A GSSAPI security context and an optional token to send back to the initiator
	//   for consumption by GSS_Init_sec_context ([SecContext.Continue()] in the Go implementation)
	//   on a partially established initiator context.
	//
	//   If [SecContext.ContinueNeeded()] returns true, additional message exchanges
	//   with the initiator are required to fully establish the security context.
	//
	//   A partially established context may allow the creation of protected messages.
	//   Check the [SecContextInfo.ProtectionReady] flag by calling [SecContext.Inquire()].
	AcceptSecContext(opts ...AcceptSecContextOption) (SecContext, error) // RFC 2743 § 2.2.2

	// ImportSecContext corresponds to the GSS_Import_sec_context function from RFC 2743 § 2.2.9
	// Parameters:
	//   b: Opaque interprocess token, generated by GSS_Export_sec_context ([SecContext.Export()] in the Go implementation)
	// Returns:
	//   A usable GSSAPI security context
	ImportSecContext(b []byte) (SecContext, error) // RFC 2743 § 2.2.9

	// InquireNamesForMech corresponds to the GSS_Inquire_names_for_mech function
	// from RFC 2743 § 2.4.12.  It returns the name types supported by a specified mechanism.
	// Parameters:
	//   m:      The GSS Name to query
	// Returns:
	//   List of name types supported, or an error
	InquireNamesForMech(m GssMech) ([]GssNameType, error) // RFC 2743 § 2.4.12

	// IndicateMechs corresponds to the GSS_Indicate_mechs function from RFC 2743 § 2.4.2.
	// Returns:
	//   List of mechanisms supported, or an error
	IndicateMechs() ([]GssMech, error) // RFC 2743 § 2.4.2

	// HasExtension reports whether a non-standard extension to GSSAPI is available
	HasExtension(e GssapiExtension) bool
}

// ProviderExtRFC5587 extends the Provider interface with RFC 5587 mechanism attribute functionality.
// Providers implementing this interface support mechanism attribute queries for indicating mechanisms
// by their attributes. Provider support for RFC 5587 can be determined with a call to
// `HasExtension(HasExtRFC5587)`.
type ProviderExtRFC5587 interface {
	Provider
	// IndicateMechsByAttrs indicates mechanisms by attributes as defined in RFC 5587 § 3.4.2.
	// The three parameters represent desired attributes, except attributes, and critical attributes respectively.
	IndicateMechsByAttrs([]GssMechAttr, []GssMechAttr, []GssMechAttr) ([]GssMech, error) // RFC 5587 § 3.4.2
}

// ProviderExtRFC5801 extends the Provider interface with RFC 5801 mechanism functionality.
// Providers implementing this interface can be used by GS2 SASL mechanisms.  Support
// for RFC 5801 can be determined with a call to `HasExtension(HasExtRFC5801)`.
type ProviderExtRFC5801 interface {
	Provider
	// InquireSASLNameForMech identified the GSSAPI mechanism to which a SASL mechanism refers
	// See RFC 5801 § 10
	InquireSASLNameForMech(m GssMech) (SASLMechInfo, error)
	// InquireMechForSASLName identifies the SASL mechanism to which a GSSAPI mechanism refers
	// See RFC 5801 § 11
	InquireMechForSASLName(saslName string) (GssMech, error)
}

type SASLMechInfo struct {
	SASLName        string
	MechName        string
	MechDescription string
}

type ProviderExtGGF interface {
	Provider
	ImportCredential(b []byte) (Credential, error) // GFD.24 § 2.1.2
}

// Acquire credentials with password extension
type ProviderExtCredPassword interface {
	Provider
	AcquireCredentialWithPassword(name GssName, password string, lifetime time.Duration, mechs []GssMech, usage CredUsage) (Credential, error)
}

type ProviderExtKrb5Identity interface {
	Provider
	RegisterAcceptorIdentity(identity string) error
	SetCCacheName(ccacheName string) error
}
