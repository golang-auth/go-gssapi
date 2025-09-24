// SPDX-License-Identifier: Apache-2.0

package gssapi

// GssapiExtension represents non-standard GSSAPI extensions that providers may support.
// The Go bindings define this type to represent extensions beyond the standard GSSAPI specification.
// Providers can advertise support for these extensions through their implementation of
// the HasExtension Provider method.
type GssapiExtension int

// GSSAPI extension constants for checking provider capabilities
const (
	// HasExtChannelBound indicates support for channel binding extensions
	HasExtChannelBound GssapiExtension = iota
	// HasExtInquireSecContextByOid indicates support for context inquiry by OID (GDF: https://ogf.org/documents/GFD.24.pdf)
	HasExtInquireSecContextByOid // GDF : https://ogf.org/documents/GFD.24.pdf
	// HasExtLocalname indicates support for local name mapping extensions (Solaris-style)
	HasExtLocalname // Solaris?
	// HasExtRFC6680 indicates support for RFC 6680 naming extensions (composite names and attributes)
	HasExtRFC6680 // RFC 6680 naming extensions
	// HasExtRFC5587 indicates support for RFC 5587 mechanism inquiry extensions (mechanism attributes)
	HasExtRFC5587 // RFC 5587 mech inquiry extensions
)
