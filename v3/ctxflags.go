// SPDX-License-Identifier: Apache-2.0

package gssapi

import "strings"

// The ContextFlag type holds the possible the security context reqest flags
type ContextFlag uint32

// GSS-API context flags - the values are the same as C bindings for compatibility
// The flags are used when initializing a security context and may be queried
// to determine the protection levels available.
const (
	ContextFlagDeleg    ContextFlag = 1 << iota // delegate credentials, not currently supported
	ContextFlagMutual                           // request remote peer authenticates itself
	ContextFlagReplay                           // enable replay detection for signed/sealed messages
	ContextFlagSequence                         // enable detection of out of sequence signed/sealed messages
	ContextFlagConf                             // request confidentiality / condidentiality available
	ContextFlagInteg                            // request integrity / integrity available
	ContextFlagAnon                             // do not transfer initiator identity to acceptor

	// extensions
	ContextFlagChannelBound = 0x800 // require channel bindings

	// Microsoft extensions - see RFC 4757 § 7.1
	ContextFlagDceStyle      = 0x1000 // add extra AP-REP from client to server after receiving server's AP-REP
	ContextFlagIdentify      = 0x2000 // server should identify the client but not impersonate it
	ContextFlagExtendedError = 0x4000 // return Windows status code in Kerberos error messages
)

// FlagList returns a slice of individual flags derived from the
// composite value f
func FlagList(f ContextFlag) (fl []ContextFlag) {
	t := ContextFlag(1)
	for i := 0; i < 32; i++ {
		if f&t != 0 {
			fl = append(fl, t)
		}

		t <<= 1
	}

	return
}

// flagName returns a human-readable description of a context flag value
func flagName(f ContextFlag) string {
	switch f {
	case ContextFlagDeleg:
		return "Delegation"
	case ContextFlagMutual:
		return "Mutual authentication"
	case ContextFlagReplay:
		return "Message replay detection"
	case ContextFlagSequence:
		return "Out of sequence message detection"
	case ContextFlagConf:
		return "Confidentiality"
	case ContextFlagInteg:
		return "Integrity"
	case ContextFlagAnon:
		return "Anonymous"
	case ContextFlagChannelBound:
		return "Channel Bindings"
	case ContextFlagDceStyle:
		return "DCE style"
	case ContextFlagIdentify:
		return "Identify only"
	case ContextFlagExtendedError:
		return "Extended errors"
	}

	return "Unknown"
}

// Returns a string describing the enabled flags
func (f ContextFlag) String() string {
	var names []string
	for _, flag := range FlagList(f) {
		names = append(names, flagName(flag))
	}

	return strings.Join(names, ", ")
}
