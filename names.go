// SPDX-License-Identifier: Apache-2.0

package gssapi

import (
	"slices"
)

//go:generate  go run ./build-tools/gen-gss-name-oids -o names_gen.go

// GssNameType describes an available GSSAPI Name Type (NT) as described in
// RFC 2743 § 4.
type GssNameType interface {
	// Oid returns the object identifier corresponding to the name type.
	Oid() Oid
	// OidString returns a printable version of the object identifier associated with the mechanism.
	OidString() string
	// String returns a printable version of the mechanism name.
	String() string
}

// gssNameTypeImpl is an internal type that implements the GssNameType interface for the
// well-known name types.  It supports well known name types.
type gssNameTypeImpl int

// GssName represents GSSAPI names (types INTERNAL NAME and MN) as described in RFC 2743 § 4.
// This interface includes support for name-related calls: GSS_Compare_name, GSS_Display_name,
// GSS_Import_name, GSS_Release_name, GSS_Inquire_mechs_for_name, GSS_Canonicalize_name,
// GSS_Export_name, and GSS_Duplicate_name.
//
// Name objects correspond to a particular name type and may optionally be associated with
// a particular GSSAPI mechanism (referred to as an MN or mechanism name).
type GssName interface {
	// Compare implements GSS_Compare_Name from RFC 2743 § 2.4.3.
	// It determines whether the two names are equal.
	//
	// Parameters:
	//   - other: the second name for comparison
	//
	// Returns:
	//   - equal: boolean value indicating whether the two names are equal
	//   - err: error if one occurred, otherwise nil
	Compare(other GssName) (equal bool, err error) // RFC 2743 § 2.4.3

	// Display implements GSS_Display_Name from RFC 2743 § 2.4.4.
	// It returns a string representation of the name and its type.
	//
	// Returns:
	//   - disp: string representation of the name
	//   - nt: type of the name
	//   - err: error if one occurred, otherwise nil
	Display() (disp string, nt GssNameType, err error) // RFC 2743 § 2.4.4

	// Release implements GSS_Release_Name from RFC 2743 § 2.4.6.
	// It releases the name when it is no longer required.
	//
	// Returns:
	//   - error if one occurred, otherwise nil
	Release() error // RFC 2743 § 2.4.6

	// InquireMechs implements GSS_Inquire_mechs_for_name from RFC 2743 § 2.4.13.
	// It returns the set of mechanisms that support the name.
	//
	// Returns:
	//   - mechs: set of mechanisms that support the name
	//   - err: error if one occurred, otherwise nil
	InquireMechs() (mechs []GssMech, err error) // RFC 2743 § 2.4.13

	// Canonicalize implements GSS_Canonicalize_name from RFC 2743 § 2.4.14.
	// It converts the name to a mechanism-specific form (MN).
	//
	// Parameters:
	//   - mech: the explicit mechanism to be used to canonicalize the name
	//
	// Returns:
	//   - name: the canonical GssName. This must be released using GssName.Release()
	//   - err: error if one occurred, otherwise nil
	Canonicalize(mech GssMech) (name GssName, err error) // RFC 2743 § 2.4.14

	// Export creates an exported byte representation of a mechanism name (MN) that is the result of
	// a call to CanonicalizeName() or Provider.AcceptSecContext().
	// It corresponds to the GSS_Export_name call defined in RFC 2743 § 2.4.15.
	//
	// The exported name can be imported using Provider.ImportName() with the GSS_NT_EXPORT_NAME
	// name type, even after the original name has been released.
	//
	// Returns:
	//   - exp: the exported name representation
	//   - err: error if one occurred, otherwise nil
	Export() (exp []byte, err error) // RFC 2743 § 2.4.15

	// Duplicate implements GSS_Duplicate_name from RFC 2743 § 2.4.16.
	// It creates a copy of the name that remains valid even if the source name is released.
	//
	// Returns:
	//   - name: the duplicated name. This must be released using GssName.Release()
	//   - err: error if one occurred, otherwise nil
	Duplicate() (name GssName, err error) // RFC 2743 § 2.4.16
}

// NOTE: if the order here changes also change
// gen-gss-name-oids.go!

const (
	// Host-based name form (RFC 2743 § 4.1),      "service@host" or just "service"
	GSS_NT_HOSTBASED_SERVICE gssNameTypeImpl = iota

	// User name form (RFC 2743 § 4.2),            "username" : named local user
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

	// Composite name type (RFC 6680 § 8)			Exported name including name attributes
	GSS_NT_COMPOSITE_EXPORT

	// Mech specific name types

	// Kerberos Principal Name (RFC 1964 § 2.1.1)           Kerberos principal name with optional @REALM
	GSS_KRB5_NT_PRINCIPAL_NAME

	// Kerberos Enterprise Principal Name (RFC 8606 § 5)    Kerberos principal alias
	GSS_KRB5_NT_ENTERPRISE_NAME

	// Kerberos X.509 DER-encoded certificate               For S4U2Self (MIT Kerberos 1.19)
	GSS_KRB5_NT_X509_CERT

	GSS_SPKM_NT_USER_NAME
	GSS_SPKM_NT_MACHINE_UID_NAME
	GSS_SPKM_NT_STRING_UID_NAME

	_GSS_NAME_TYPE_LAST
)

func (nt gssNameTypeImpl) Oid() Oid {
	if nt >= _GSS_NAME_TYPE_LAST {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oid
}

func (nt gssNameTypeImpl) OidString() string {
	if nt >= _GSS_NAME_TYPE_LAST {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oidString
}

func (nt gssNameTypeImpl) String() string {
	if nt >= _GSS_NAME_TYPE_LAST {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].name
}

// NameTypeFromOid returns the name type associated with an OID.
//
// The standard implementation offers this function for use with the gssNameTypeImpl
// internal type for a standard set of well known name types.
//
// If a provider needs to support a different name type, it can be added to gssNameTypeImpl via a pull
// request to the go-gssapi repository. Alternatively, a new implementation of GssNameType can be
// created for use by that GSSAPI implementation. Depending on the requirements, a replacement for
// NameTypeFromOid may also need to be provided by the provider.
// This function is provided to map a name OID to a name type.
//
// Parameters:
//   - oid: the object identifier to look up
//
// Returns:
//   - gssNameTypeImpl: the corresponding name type
//   - error: ErrBadNameType if the OID is not recognized
func NameTypeFromOid(oid Oid) (gssNameTypeImpl, error) {
	for i, nt := range nameTypes {
		if slices.Equal(nt.oid, oid) {
			return gssNameTypeImpl(i), nil
		}

		for _, alt := range nt.altOids {
			if slices.Equal(alt, oid) {
				return gssNameTypeImpl(i), nil
			}
		}
	}

	return 0, ErrBadNameType
}

// Extensions

// InquireNameInfo contains information about a name returned by the Inquire method
// in the RFC 6680 naming extensions.
type InquireNameInfo struct {
	IsMechName bool     // Whether the name is a mechanism name (MN)
	Mech       GssMech  // The mechanism associated with the name, if IsMechName is true
	Attributes []string // List of attribute names associated with the name
}

// NameAttributes represents the attributes of a name as defined in RFC 6680.
type NameAttributes struct {
	Authenticated bool     // Whether the attributes are authenticated
	Complete      bool     // Whether the attribute set is complete
	Values        []string // The attribute values
	DisplayValues []string // Human-readable versions of the attribute values
}

// GssNameExtRFC6680 extends GssName with RFC 6680 composite name features.
// Names that support RFC 6680 composite name features implement this interface.
// Provider support for RFC 6680 can be verified with a call to HasExtension(HasExtRFC6680).
type GssNameExtRFC6680 interface {
	GssName
	// DisplayExt displays a name in the specified name type format as defined in RFC 6680 § 7.3.
	DisplayExt(GssNameType) (string, error) // RFC 6680 § 7.3

	// Inquire returns information about the name as defined in RFC 6680 § 7.4.
	Inquire() (InquireNameInfo, error) // RFC 6680 § 7.4

	// GetAttributes retrieves attributes for the specified attribute name as defined in RFC 6680 § 7.5.
	GetAttributes(string) (NameAttributes, error) // RFC 6680 § 7.5

	// SetAttributes sets attributes for the name as defined in RFC 6680 § 7.6.
	SetAttributes(bool, string, []string) error // RFC 6680 § 7.6

	// DeleteNameAttributes deletes the specified attribute from the name as defined in RFC 6680 § 7.7.
	DeleteNameAttributes(string) error // RFC 6680 § 7.7

	// ExportComposite exports the name in composite format as defined in RFC 6680 § 7.8.
	ExportComposite() ([]byte, error) // RFC 6680 § 7.8
}

// GssNameExtLocalname extends GssName with local name mapping functionality.
// For systems that support local name mapping, names may implement this interface.
// Provider local name support can be checked with a call to HasExtension(HasExtLocalname).
type GssNameExtLocalname interface {
	GssName
	// Localname maps the name to a local system name for the specified mechanism.
	Localname(GssMech) (string, error)
}
