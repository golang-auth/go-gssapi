// SPDX-License-Identifier: Apache-2.0

package gssapi

import "net"

// GssAddressFamily defines address family constants used in channel bindings.
// These constants correspond to the address family values used in GSSAPI channel bindings.
type GssAddressFamily int

// Address family constants for channel bindings
const (
	GssAddrFamilyUNSPEC  GssAddressFamily = iota // Unspecified address family
	GssAddrFamilyLOCAL                           // Local to host (pipes, etc.)
	GssAddrFamilyINET                            // Internet Protocol version 4
	GssAddrFamilyIMPLINK                         // ARPANET IMP addresses
	GssAddrFamilyPUP                             // PUP protocols
	GssAddrFamilyCHAOS                           // MIT CHAOS protocols
	GssAddrFamilyNS                              // XEROX Network Systems
	GssAddrFamilyNBS                             // NBS protocols
	GssAddrFamilyECMA                            // European Computer Manufacturers Association
	GssAddrFamilyDATAKIT                         // DATAKIT protocols
	GssAddrFamilyCCITT                           // CCITT protocols, X.25 etc
	GssAddrFamilySNA                             // IBM SNA protocols
	GssAddrFamilyDECnet                          // DECnet protocols
	GssAddrFamilyDLI                             // DEC Direct data link interface
	GssAddrFamilyLAT                             // LAT protocols
	GssAddrFamilyHYLINK                          // NSC Hyperchannel
	GssAddrFamilyAPPLETA                         // Apple Talk protocols
	GssAddrFamilyBSC                             // IBM BSC protocols
	GssAddrFamilyDSS                             // Distributed system services
	GssAddrFamilyOSI                             // OSI protocols
	GssAddrFamilyNETBIOS                         // NetBIOS protocols
	GssAddrFamilyX25                             // X.25 protocols
)

// ChannelBinding represents channel binding information used to bind a security context
// to a communication channel. The Go bindings define this type to represent channel binding
// information as described in the GSSAPI specification.
//
// Channel bindings provide additional security by cryptographically binding the GSSAPI
// authentication to properties of the underlying communication channel, making it more
// difficult for an attacker to hijack the connection.
type ChannelBinding struct {
	InitiatorAddr net.Addr // Network address of the initiator
	AcceptorAddr  net.Addr // Network address of the acceptor
	Data          []byte   // Application-specific channel binding data
}
