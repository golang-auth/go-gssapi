// SPDX-License-Identifier: Apache-2.0

package gssapi

import "slices"

//go:generate  go run ./build-tools/gen-gss-mech-attrs -o mech_attrs_gen.go

// GssMechAttr represents mechanism attributes as defined in RFC 5587. The Go bindings support
// mechanism attributes for describing the capabilities and properties of GSSAPI mechanisms.
type GssMechAttr interface {
	// Oid returns the object identifier corresponding to the mechanism attribute.
	Oid() Oid
	// OidString returns a printable version of the object identifier associated with the mechanism attribute.
	OidString() string
	// String returns a printable version of the mechanism attribute name.
	String() string
	// Display returns human-readable information about the mechanism attribute as defined in RFC 5587 § 3.4.4.
	// Returns the attribute name, short description, and long description respectively.
	Display() (string, string, string, error) // RFC 5587 § 3.4.4
}

// gssMechAttrImpl defines mechanism attributes (RFC 5587). The standard implementation provides many well-known
// mechanism attributes including GSS_MA_MECH_CONCRETE, GSS_MA_MECH_PSEUDO, GSS_MA_MECH_COMPOSITE (Mechanism types),
// GSS_MA_AUTH_INIT, GSS_MA_AUTH_TARG (Authentication capabilities), GSS_MA_DELEG_CRED (Credential delegation support),
// GSS_MA_INTEG_PROT, GSS_MA_CONF_PROT (Protection services), GSS_MA_REPLAY_DET, GSS_MA_OOS_DET (Message ordering detection),
// GSS_MA_CBINDINGS (Channel binding support), and many others as defined in RFC 5587.
type gssMechAttrImpl int

// Well known Mechanism attributes (RFC 5587)
const (
	// GSS_MA_MECH_CONCRETE - Indicates that a mechanism is neither a pseudo-mechanism nor a composite mechanism.
	GSS_MA_MECH_CONCRETE gssMechAttrImpl = iota
	// GSS_MA_MECH_PSEUDO - Indicates that a mechanism is a pseudo-mechanism.
	GSS_MA_MECH_PSEUDO
	// GSS_MA_MECH_COMPOSITE - Indicates that a mechanism is a composite of other mechanisms.
	// This is reserved for a specification of stackable pseudo-mechanisms.
	GSS_MA_MECH_COMPOSITE
	// GSS_MA_MECH_NEGO - Indicates that a mechanism negotiates other mechanisms.
	// eg. SPNEGO has this attribute.
	GSS_MA_MECH_NEGO
	// GSS_MA_MECH_GLUE - Indicates that the OID is not for a mechanism but for GSSAPI itself
	GSS_MA_MECH_GLUE
	// GSS_MA_NOT_MECH - Indicates that the OID is know, yet is is also known not to be the OID of
	// any GSSAPI mechanism or of the GSSAPI itself.
	GSS_MA_NOT_MECH
	// GSS_MA_DEPRECATED - Indicates that a mechanism or its OID is deprecated and must not be
	// used as a default mechanism.
	GSS_MA_DEPRECATED
	// GSS_MA_NOT_DFLT_MECH - Indicates that a mechanism or its OID must not be used as a default mechanism.
	GSS_MA_NOT_DFLT_MECH
	// GSS_MA_ITOK_FRAMED - Indicates that a mechanism's initial context tokens are properly framed
	// as per RFC2743 § 3.1.
	GSS_MA_ITOK_FRAMED
	// GSS_MA_AUTH_INIT - Indicates support for authentication of initiator to acceptor.
	GSS_MA_AUTH_INIT
	// GSS_MA_AUTH_TARG - Indicates support for authentication of acceptor to initiator.
	GSS_MA_AUTH_TARG
	// GSS_MA_AUTH_INIT_INIT - Indicates support for authentication of initiator
	// to acceptor.  Initial authentication refers to the use of passwords, or keys stored on tokens
	// for authentication.  Whether a mechanism supports initial authentcation may depend on IETF
	// consensus.
	GSS_MA_AUTH_INIT_INIT
	// GSS_MA_AUTH_TARG_INIT - Indicates support for initial authentication of acceptor to initiator.
	GSS_MA_AUTH_TARG_INIT
	// GSS_MA_AUTH_INIT_ANON - Indicates support for GSS_NT_ANONYMOUS as an initiator principal
	// name.
	GSS_MA_AUTH_INIT_ANON
	// GSS_MA_AUTH_TARG_ANON - Indicates support for GSS_NT_ANONYMOUS as an target principal
	// name.
	GSS_MA_AUTH_TARG_ANON
	// GSS_MA_DELEG_CRED - Indicates support for credential delegation.
	GSS_MA_DELEG_CRED
	// GSS_MA_INTEG_PROT - Indicates support for per-message integrity protection.
	GSS_MA_INTEG_PROT
	// GSS_MA_CONF_PROT - Indicates support for per-message confidentiality protection.
	GSS_MA_CONF_PROT
	// GSS_MA_MIC - Indicates support for Message Integrity Code (MIC) tokens.
	GSS_MA_MIC
	// GSS_MA_WRAP - Indicates support for wrap tokens.
	GSS_MA_WRAP
	// GSS_MA_PROT_READY - Indicates support for per-message protection prior to full context establishment.
	GSS_MA_PROT_READY
	// GSS_MA_REPLAY_DET - Indicates support for replay detection.
	GSS_MA_REPLAY_DET
	// GSS_MA_OOS_DET - Indicates support for out-of-sequence detection.
	GSS_MA_OOS_DET
	// GSS_MA_CBINDINGS - Indicates support for channel bindings.
	GSS_MA_CBINDINGS
	// GSS_MA_PFS - Indicates support for Perfect Forward Security.
	GSS_MA_PFS
	// GSS_MA_COMPRESS - Indicates support for compression of data inputs to gss_wrap().
	GSS_MA_COMPRESS
	// GSS_MA_CTX_TRANS - Indicates support for security context export/import.
	GSS_MA_CTX_TRANS
	// GSS_MA_NEGOEX_AND_SPNEGO - Indicates that the NegoEx mechanism should also be negotiable through SPNEGO.
	GSS_MA_NEGOEX_AND_SPNEGO

	_GSS_MA_LAST
)

func (attr gssMechAttrImpl) Oid() Oid {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].oid
}

func (attr gssMechAttrImpl) OidString() string {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].oidString
}

func (attr gssMechAttrImpl) String() string {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].mech
}

func (attr gssMechAttrImpl) Display() (string, string, string, error) {
	if attr >= _GSS_MA_LAST {
		panic(ErrBadMechAttr)
	}

	return mechAttrs[attr].mech, mechAttrs[attr].shortDesc, mechAttrs[attr].longDesc, nil
}

// MechAttrFromOid returns a mechanism attribute implementation from an OID.
// This function maps an OID to the corresponding mechanism attribute.
//
// Parameters:
//   - oid: the object identifier to look up
//
// Returns:
//   - gssMechAttrImpl: the corresponding mechanism attribute implementation
//   - error: ErrBadMechAttr if the OID is not recognized
func MechAttrFromOid(oid Oid) (gssMechAttrImpl, error) {
	for i, attr := range mechAttrs {
		if slices.Equal(attr.oid, oid) {
			return gssMechAttrImpl(i), nil
		}
	}

	return 0, ErrBadMechAttr
}
