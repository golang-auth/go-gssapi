// SPDX-License-Identifier: Apache-2.0

package gssapi

// GssapiExtension represents non-standard GSSAPI extensions that providers may support.
// The Go bindings define this type to represent extensions beyond the standard GSSAPI specification.
// Providers can advertise support for these extensions through their implementation of
// the HasExtension Provider method.
type GssapiExtension int

// GSSAPI extension constants for checking provider capabilities
const (
	// HasExtChannelBindingSignalling indicates support for channel binding signalling extensions
	//  (https://datatracker.ietf.org/doc/html/draft-williams-kitten-channel-bound-flag-02)
	HasExtChannelBindingSignalling GssapiExtension = iota
	// HasExtLocalname indicates support for local name mapping extensions (Solaris-style)
	HasExtLocalname
	// HasExtRFC4178 indicates support for the credential APIs defined in RFC 4178: GSSAPI Negotiation mechamisn
	HasExtRFC4178
	// HasExtRFC5588 indicates support for the credential APIs defined in RFC 5588: Storing delegated credentials
	HasExtRFC5588
	// HasExtRFC6680 indicates support for RFC 6680 naming extensions (composite names and attributes)
	HasExtRFC6680
	// HasExtRFC5587 indicates support for RFC 5587 mechanism inquiry extensions (mechanism attributes)
	HasExtRFC5587
	// HasExtRFC5801 indicates support for RFC 5801 Mechanisms in SASL Negotiation
	HasExtRFC5801
	// HasExtRFC4121 indicates support for RFC 4121: AEAD modes for Kerberos GSSAPI
	HasExtRFC4121
	// HasExtGGF indicates support for GGF extensions (GDF: https://ogf.org/documents/GFD.24.pdf)
	HasExtGGF
	// HasS4U indicates support for Service4user constrained delegation extensions
	HasS4U
	// HasExtCredPassword indicates support for acquiring credentials using passwords
	HasExtCredPassword
)
