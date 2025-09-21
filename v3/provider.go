// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"sync"
	"time"
)

var registry struct {
	sync.Mutex
	libs map[string]ProviderFactory
}

func init() {
	registry.libs = make(map[string]ProviderFactory)
}

type ProviderFactory func() Provider

func RegisterProvider(name string, f ProviderFactory) {
	registry.Lock()
	defer registry.Unlock()

	registry.libs[name] = f
}

func NewProvider(name string) Provider {
	registry.Lock()
	defer registry.Unlock()

	if name == "" {
		panic("GSSAPI library name not set")
	}

	f, ok := registry.libs[name]
	if !ok {
		panic("GSSAPI library not found: " + name)
	}

	return f()
}

type QoP uint

type InitSecContextOptions struct {
	Credential     Credential
	Mech           GssMech
	Flags          ContextFlag
	Lifetime       time.Duration
	ChannelBinding *ChannelBinding
}

type InitSecContextOption func(o *InitSecContextOptions)

func WithInitiatorCredential(cred Credential) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Credential = cred
	}
}

func WithInitiatorMech(mech GssMech) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Mech = mech
	}
}

func WithInitiatorFlags(flags ContextFlag) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Flags = flags
	}
}

func WithInitiatorLifetime(life time.Duration) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.Lifetime = life
	}
}

func WithChannelBinding(cb *ChannelBinding) InitSecContextOption {
	return func(o *InitSecContextOptions) {
		o.ChannelBinding = cb
	}
}

type GssapiExtension int

const (
	GssapiExtHasChannelBound           GssapiExtension = iota
	GssapiExtHasInquireSecContextByOid                 // where is this defined in the MIT source ?    https://ogf.org/documents/GFD.24.pdf
	GssapiExtHasInquireName                            // RFC 6680 § 7.4
	GssapiExtHasGetNameAttributes                      // RFC 6680 § 7.5
	GssapiExtHasSetNameAttributes                      // RFC 6680 § 7.6
	GssapiExtHasDeleteNameAttributes                   // RFC 6680 § 7.7
	GssapiExtHasExportNameComposite                    // RFC 6680 § 7.8
	GssapiExtHasIndicateMechsByAttrs                   // RFC 5587 § 3.4.2
	GssapiExtHasInquireAttrsForMech                    // RFC 5587 § 3.4.3
	GssapiExtHasDisplayMechAttr                        // RFC 5587 § 3.4.4
)

// TODO: Add mech attrs fom RFC 5587
// SPNEGO in RFC 4187

// Provider is the interface that defines the top level GSSAPI functions that
// create name, credential and security contexts
type Provider interface {
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
	AcquireCredential(name GssName, mechs []GssMech, usage CredUsage, lifetime time.Duration) (Credential, error) // RFC 2743 § 2.1.1

	// NOTE:  RFC7546

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
	//   cred: The GSSAPI acceptor credential, or nil to use the default.
	//   cb:   Channel bindings information, or nil for no channel bindings
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
	AcceptSecContext(cred Credential, cb *ChannelBinding) (SecContext, error) // RFC 2743 § 2.2.2

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
