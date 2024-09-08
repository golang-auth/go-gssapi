// SPDX-License-Identifier: Apache-2.0
package gssapi

import "net"

type GssAddressFamily int

const (
	GssAddrFamilyUNSPEC GssAddressFamily = 0
	GssAddrFamilyLOCAL  GssAddressFamily = 1 << iota
	GssAddrFamilyINET
	GssAddrFamilyIMPLINK
	GssAddrFamilyPUP
	GssAddrFamilyCHAOS
	GssAddrFamilyNS
	GssAddrFamilyNBS
	GssAddrFamilyECMA
	GssAddrFamilyDATAKIT
	GssAddrFamilyCCITT
	GssAddrFamilySNA
	GssAddrFamilyDECnet
	GssAddrFamilyDLI
	GssAddrFamilyLAT
	GssAddrFamilyHYLINK
	GssAddrFamilyAPPLETA
	GssAddrFamilyBSC
	GssAddrFamilyDSS
	GssAddrFamilyOSI
	GssAddrFamilyNETBIOS
	GssAddrFamilyX25
)

type ChannelBinding struct {
	InitiatorAddr net.Addr
	AcceptorAddr  net.Addr
	Data          []byte
}
