// SPDX-License-Identifier: Apache-2.0

package gssapi

// GENERATED CODE: DO NOT EDIT

var nameTypes = []struct {
	id        gssNameTypeImpl
	name      string
	oidString string
	oid       Oid
	altOids   []Oid
}{
	

	// 1.2.840.113554.1.2.1.4
	{ GSS_NT_HOSTBASED_SERVICE,
		"GSS_NT_HOSTBASED_SERVICE",
		"1.2.840.113554.1.2.1.4",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04 },
		[]Oid{
		   {0x2b, 0x06, 0x01, 0x05, 0x06, 0x02 }, // 1.3.6.1.5.6.2
		  }},

	// 1.2.840.113554.1.2.1.1
	{ GSS_NT_USER_NAME,
		"GSS_NT_USER_NAME",
		"1.2.840.113554.1.2.1.1",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.1.2
	{ GSS_NT_MACHINE_UID_NAME,
		"GSS_NT_MACHINE_UID_NAME",
		"1.2.840.113554.1.2.1.2",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x02 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.1.3
	{ GSS_NT_STRING_UID_NAME,
		"GSS_NT_STRING_UID_NAME",
		"1.2.840.113554.1.2.1.3",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x03 },
		[]Oid{ }},

	// 1.3.6.1.5.6.3
	{ GSS_NT_ANONYMOUS,
		"GSS_NT_ANONYMOUS",
		"1.3.6.1.5.6.3",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x06, 0x03 },
		[]Oid{ }},

	// 
	{ GSS_NO_OID,
		"GSS_NO_OID",
		"",
		nil,
		[]Oid{ }},

	// 1.3.6.1.5.6.4
	{ GSS_NT_EXPORT_NAME,
		"GSS_NT_EXPORT_NAME",
		"1.3.6.1.5.6.4",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x06, 0x04 },
		[]Oid{ }},

	// 
	{ GSS_NO_NAME,
		"GSS_NO_NAME",
		"",
		nil,
		[]Oid{ }},

	// 1.3.6.1.5.6.6
	{ GSS_NT_COMPOSITE_EXPORT,
		"GSS_NT_COMPOSITE_EXPORT",
		"1.3.6.1.5.6.6",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x06, 0x06 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.2.1
	{ GSS_KRB5_NT_PRINCIPAL_NAME,
		"GSS_KRB5_NT_PRINCIPAL_NAME",
		"1.2.840.113554.1.2.2.1",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01 },
		[]Oid{
		   {0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 }, // 1.2.840.48018.1.2.2
		  }},

	// 1.2.840.113554.1.2.2.6
	{ GSS_KRB5_NT_ENTERPRISE_NAME,
		"GSS_KRB5_NT_ENTERPRISE_NAME",
		"1.2.840.113554.1.2.2.6",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.2.7
	{ GSS_KRB5_NT_X509_CERT,
		"GSS_KRB5_NT_X509_CERT",
		"1.2.840.113554.1.2.2.7",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x07 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.1.1
	{ GSS_SPKM_NT_USER_NAME,
		"GSS_SPKM_NT_USER_NAME",
		"1.2.840.113554.1.2.1.1",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.1.2
	{ GSS_SPKM_NT_MACHINE_UID_NAME,
		"GSS_SPKM_NT_MACHINE_UID_NAME",
		"1.2.840.113554.1.2.1.2",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x02 },
		[]Oid{ }},

	// 1.2.840.113554.1.2.1.3
	{ GSS_SPKM_NT_STRING_UID_NAME,
		"GSS_SPKM_NT_STRING_UID_NAME",
		"1.2.840.113554.1.2.1.3",
		[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x03 },
		[]Oid{ }},

}

