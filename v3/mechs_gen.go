package gssapi

// GENERATED CODE: DO NOT EDIT

var mechs = []struct {
	id        gssMechImpl
	mech      string
	oidString string
	oid       Oid
	altOids   []Oid
}{

	// 1.2.840.113554.1.2.2
	{GSS_MECH_KRB5,
		"GSS_MECH_KRB5",
		"1.2.840.113554.1.2.2",
		[]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2},
		[]Oid{
			{0x2b, 0x6, 0x1, 0x5, 0x2}, // 1.3.6.1.5.2

			{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x1, 0x2, 0x2}, // 1.2.840.48018.1.2.2
		}},

	// 1.3.6.1.5.2.5
	{GSS_MECH_IAKERB,
		"GSS_MECH_IAKERB",
		"1.3.6.1.5.2.5",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x2, 0x5},
		[]Oid{}},

	// 1.3.6.1.5.5.2
	{GSS_MECH_SPNEGO,
		"GSS_MECH_SPNEGO",
		"1.3.6.1.5.5.2",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x5, 0x2},
		[]Oid{}},

	// 1.3.6.1.5.5.1.1
	{GSS_MECH_SPKM - 1,
		"GSS_MECH_SPKM-1",
		"1.3.6.1.5.5.1.1",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x5, 0x1, 0x1},
		[]Oid{}},

	// 1.3.6.1.5.5.1.2
	{GSS_MECH_SPKM - 2,
		"GSS_MECH_SPKM-2",
		"1.3.6.1.5.5.1.2",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x5, 0x1, 0x2},
		[]Oid{}},

	// 1.3.6.1.5.5.1.3
	{GSS_MECH_SPKM - 3,
		"GSS_MECH_SPKM-3",
		"1.3.6.1.5.5.1.3",
		[]byte{0x2b, 0x6, 0x1, 0x5, 0x5, 0x1, 0x3},
		[]Oid{}},
}
