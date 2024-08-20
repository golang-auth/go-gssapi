// SPDX-License-Identifier: Apache-2.0
package gssapi

import (
	"slices"
)

//go:generate  go run ../build-tools/gen-gss-name-oids.go -o names_gen.go

// GssNameType defines the name types in a mech-independent fashion,
// as described in RFC 2743 § 4
type GssNameType int

type GssName interface {
	Compare(other GssName) (bool, error)   // RFC 2743 § 2.4.3
	Display() (string, GssNameType, error) // RFC 2743 § 2.4.3
	Release() error                        // RFC 2743 § 2.4.6
	InquireMechs() ([]GssMech, error)      // RFC 2743 § 2.4.13
	Canonicalize(GssMech) (GssName, error) // RFC 2743 § 2.4.14
	Export() ([]byte, error)               // RFC 2743 § 2.4.15
	Duplicate() (GssName, error)           // RFC 2743 § 2.4.16
}

const (
	// Host-based name form (RFC 2743 § 4.1),      "service@host" or just "service"
	GSS_NT_HOSTBASED_SERVICE GssNameType = iota

	// User namne form (RFC 2743 § 4.2),           "username" : named local user
	GSS_NT_USER_NAME

	// Machine UID form (RFC 2743 § 4.3),           Numeric user ID in host byte order; use gss_import_name to convert to user name form
	GSS_NT_MACHINE_UID_NAME

	// Machine UID form (RFC 2743 § 4.4),           Same as GSS_NT_MACHINE_UID_NAME but as a string of digits
	GSS_NT_STRING_UID_NAME

	// Anonymous name type (RFC 2743 § 4.5),        an anonymous principal
	GSS_NT_ANONYMOUS

	// Default name type (RFC 2743 § 4.6),          Null input value, not an actual OID; indicates name based on mech-specific default syntax
	GSS_NO_OID

	// Exported name type (RFC 2743 § 4.7),         Mech-independent exported name type from RFC 2743 § 3.2
	GSS_NT_EXPORT_NAME

	// No name type (RFC 2743 § 4.8),               Indicates that no name is being passed;  used only in gss_acquire_cred, gss_add_cred, gss_init_sec_context
	GSS_NO_NAME

	// Mech specific name types

	// Kerberos Principal Name (RFC 1964 § 2.1.1)           Kerberos prinicpal name with optional @REALM
	GSS_KRB5_NT_PRINCIPAL_NAME

	// Kerberos Enterprise Principal Name (RFC 8606 § 5)    Kerberos principal alias
	GSS_KRB5_NT_ENTERPRISE_NAME

	// Kerberos X.509 DER-encoded certificate               For S4U2Self (MIT Kerberos 1.19)
	GSS_KRB5_NT_X509_CERT

	GSS_SPKM_NT_USER_NAME
	GSS_SPKM_NT_MACHINE_UID_NAME
	GSS_SPKM_NT_STRING_UID_NAME
)

func (nt GssNameType) Oid() Oid {
	if nt > GSS_KRB5_NT_X509_CERT {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oid
}

func (nt GssNameType) OidString() string {
	if nt > GSS_KRB5_NT_X509_CERT {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oidString
}

func (nt GssNameType) String() string {
	if nt > GSS_KRB5_NT_X509_CERT {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].name
}

func NameFromOid(oid Oid) (GssNameType, error) {
	for i, nt := range nameTypes {
		if slices.Equal(nt.oid, oid) {
			return GssNameType(i), nil
		}

		for _, alt := range nt.altOids {
			if slices.Equal(alt, oid) {
				return GssNameType(i), nil
			}
		}
	}

	return 0, ErrBadNameType
}
