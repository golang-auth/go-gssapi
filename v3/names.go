package gssapi

import (
	"slices"
)

// GssNameType defines the name types in a mech-independent fashion,
// as described in RFC 2743 § 4
type GssNameType int

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
	GSS_C_NT_ANONYMOUS

	// Default name type (RFC 2743 § 4.6),          Null input value, not an actual OID; indicates name based on mech-specific default syntax
	GSS_NO_OID

	// Exported name type (RFC 2743 § 4.7),         Mech-independent exported name type from RFC 2743 § 3.2
	GSS_EXPORT_NAME

	// No name type (RFC 2743 § 4.8),               Indicates that no name is being passed;  used only in gss_acquire_cred, gss_add_cred, gss_init_sec_context
	GSS_NO_NAME
)

// order here needs to match the consts above!
var nameTypes = []struct {
	id        GssNameType
	name      string
	oidString string
	oid       Oid
	altOids   []Oid
}{
	// 1.2.840.113554.1.2.1.4
	{GSS_NT_HOSTBASED_SERVICE,
		"GSS_NT_HOSTBASED_SERVICE",
		"1.2.840.113554.1.2.1.4",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04},
		[]Oid{{0x2B, 0x06, 0x01, 0x05, 0x06, 0x02}}}, // 1.3.6.1.5.6.2                alternate value from RFC 2078

	// 1.2.840.113554.1.2.1.1
	{GSS_NT_USER_NAME,
		"GSS_NT_USER_NAME",
		"1.2.840.113554.1.2.1.1",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01}, []Oid{}},

	// 1.2.840.113554.1.2.1.2
	{GSS_NT_MACHINE_UID_NAME,
		"GSS_NT_MACHINE_UID_NAME",
		"1.2.840.113554.1.2.1.2",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x02}, []Oid{}},

	// 1.2.840.113554.1.2.1.3
	{GSS_NT_STRING_UID_NAME,
		"GSS_NT_STRING_UID_NAME",
		"1.2.840.113554.1.2.1.3",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x03}, []Oid{}},

	// 1.3.6.1.5.6.3
	{GSS_C_NT_ANONYMOUS,
		"GSS_C_NT_ANONYMOUS",
		"1.3.6.1.5.6.3",
		[]byte{0x2b, 0x06, 0x01, 0x05, 0x06, 0x03}, []Oid{}},

	{GSS_NO_OID, "GSS_NO_OID", "", nil, []Oid{}},

	// 1.3.6.1.5.6.4
	{GSS_EXPORT_NAME,
		"GSS_EXPORT_NAME",
		"1.3.6.1.5.6.4",
		[]byte{0x2b, 0x06, 0x01, 0x05, 0x06, 0x04}, []Oid{}},

	{GSS_NO_NAME, "GSS_NO_NAME", "", nil, []Oid{}},
}

func (nt GssNameType) Oid() Oid {
	if nt > GSS_NO_NAME {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oid
}

func (nt GssNameType) OidString() string {
	if nt > GSS_NO_NAME {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].oidString
}

func (nt GssNameType) String() string {
	if nt > GSS_NO_NAME {
		panic(ErrBadNameType)
	}

	return nameTypes[nt].name
}

func FromOid(oid Oid) (GssNameType, error) {
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
