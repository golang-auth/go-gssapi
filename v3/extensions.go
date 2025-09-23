package gssapi

type GssapiExtension int

const (
	HasExtChannelBound           GssapiExtension = iota
	HasExtInquireSecContextByOid                 // GDF : https://ogf.org/documents/GFD.24.pdf
	HasExtLocalname                              // Solaris?
	HasExtRFC6680                                // RFC 6680 naming extensions
	HasExtRFC5587                                // RFC 5587 mech inquiry extensions
)
