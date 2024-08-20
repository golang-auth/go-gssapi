package gssapi

// GENERATED CODE: DO NOT EDIT

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
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x4},
		[]Oid{
			{0x2b, 0x6, 0x1, 0x5, 0x6, 0x2}, // 1.3.6.1.5.6.2
		}},

	// 1.2.840.113554.1.2.1.1
	{GSS_NT_USER_NAME,
		"GSS_NT_USER_NAME",
		"1.2.840.113554.1.2.1.1",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x1},
		[]Oid{}},

	// 1.2.840.113554.1.2.1.2
	{GSS_NT_MACHINE_UID_NAME,
		"GSS_NT_MACHINE_UID_NAME",
		"1.2.840.113554.1.2.1.2",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x2},
		[]Oid{}},

	// 1.2.840.113554.1.2.1.3
	{GSS_NT_STRING_UID_NAME,
		"GSS_NT_STRING_UID_NAME",
		"1.2.840.113554.1.2.1.3",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x3},
		[]Oid{}},

	// 1.3.6.1.5.6.3
	{GSS_NT_ANONYMOUS,
		"GSS_NT_ANONYMOUS",
		"1.3.6.1.5.6.3",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x6, 0x3},
		[]Oid{}},

	//
	{GSS_NO_OID,
		"GSS_NO_OID",
		"",
		nil,
		[]Oid{}},

	// 1.3.6.1.5.6.4
	{GSS_NT_EXPORT_NAME,
		"GSS_NT_EXPORT_NAME",
		"1.3.6.1.5.6.4",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x6, 0x4},
		[]Oid{}},

	//
	{GSS_NO_NAME,
		"GSS_NO_NAME",
		"",
		nil,
		[]Oid{}},

	// 1.2.840.113554.1.2.2.1
	{GSS_KRB5_NT_PRINCIPAL_NAME,
		"GSS_KRB5_NT_PRINCIPAL_NAME",
		"1.2.840.113554.1.2.2.1",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x1},
		[]Oid{
			{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x1, 0x2, 0x2}, // 1.2.840.48018.1.2.2
		}},

	// 1.2.840.113554.1.2.2.6
	{GSS_KRB5_NT_ENTERPRISE_NAME,
		"GSS_KRB5_NT_ENTERPRISE_NAME",
		"1.2.840.113554.1.2.2.6",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x6},
		[]Oid{}},

	// 1.2.840.113554.1.2.2.7
	{GSS_KRB5_NT_X509_CERT,
		"GSS_KRB5_NT_X509_CERT",
		"1.2.840.113554.1.2.2.7",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x7},
		[]Oid{}},

	// 1.2.840.113554.1.2.1.1
	{GSS_SPKM_NT_USER_NAME,
		"GSS_SPKM_NT_USER_NAME",
		"1.2.840.113554.1.2.1.1",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x1},
		[]Oid{}},

	// 1.2.840.113554.1.2.1.2
	{GSS_SPKM_NT_MACHINE_UID_NAME,
		"GSS_SPKM_NT_MACHINE_UID_NAME",
		"1.2.840.113554.1.2.1.2",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x2},
		[]Oid{}},

	// 1.2.840.113554.1.2.1.3
	{GSS_SPKM_NT_STRING_UID_NAME,
		"GSS_SPKM_NT_STRING_UID_NAME",
		"1.2.840.113554.1.2.1.3",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x1, 0x3},
		[]Oid{}},
}
