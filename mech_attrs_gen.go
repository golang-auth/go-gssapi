// SPDX-License-Identifier: Apache-2.0

package gssapi

// GENERATED CODE: DO NOT EDIT

var mechAttrs = []struct {
	id        gssMechAttrImpl
	mech      string
	shortDesc string
	longDesc  string
	oidString string
	oid       Oid
}{


	// 1.3.6.1.5.5.13.1
	{ GSS_MA_MECH_CONCRETE,
		"GSS_MA_MECH_CONCRETE",
		"concrete-mech",
		"Mechanism is neither a pseudo-mechanism nor a composite mechanism.",
		"1.3.6.1.5.5.13.1",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x01 },
    },

	// 1.3.6.1.5.5.13.2
	{ GSS_MA_MECH_PSEUDO,
		"GSS_MA_MECH_PSEUDO",
		"pseudo-mech",
		"Mechanism is a pseudo-mechanism.",
		"1.3.6.1.5.5.13.2",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x02 },
    },

	// 1.3.6.1.5.5.13.3
	{ GSS_MA_MECH_COMPOSITE,
		"GSS_MA_MECH_COMPOSITE",
		"composite-mech",
		"Mechanism is a composite of other mechanisms.",
		"1.3.6.1.5.5.13.3",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x03 },
    },

	// 1.3.6.1.5.5.13.4
	{ GSS_MA_MECH_NEGO,
		"GSS_MA_MECH_NEGO",
		"mech-negotiation-mech",
		"Mechanism negotiates other mechanisms.",
		"1.3.6.1.5.5.13.4",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x04 },
    },

	// 1.3.6.1.5.5.13.5
	{ GSS_MA_MECH_GLUE,
		"GSS_MA_MECH_GLUE",
		"mech-glue",
		"OID is not a mechanism but the GSS-API itself.",
		"1.3.6.1.5.5.13.5",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x05 },
    },

	// 1.3.6.1.5.5.13.6
	{ GSS_MA_NOT_MECH,
		"GSS_MA_NOT_MECH",
		"not-mech",
		"Known OID but not a mechanism OID.",
		"1.3.6.1.5.5.13.6",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x06 },
    },

	// 1.3.6.1.5.5.13.7
	{ GSS_MA_DEPRECATED,
		"GSS_MA_DEPRECATED",
		"mech-deprecated",
		"Mechanism is deprecated.",
		"1.3.6.1.5.5.13.7",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x07 },
    },

	// 1.3.6.1.5.5.13.8
	{ GSS_MA_NOT_DFLT_MECH,
		"GSS_MA_NOT_DFLT_MECH",
		"mech-not-default",
		"Mechanism must not be used as a default mechanism.",
		"1.3.6.1.5.5.13.8",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x08 },
    },

	// 1.3.6.1.5.5.13.9
	{ GSS_MA_ITOK_FRAMED,
		"GSS_MA_ITOK_FRAMED",
		"initial-is-framed",
		"Mechanism's initial contexts are properly framed.",
		"1.3.6.1.5.5.13.9",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x09 },
    },

	// 1.3.6.1.5.5.13.10
	{ GSS_MA_AUTH_INIT,
		"GSS_MA_AUTH_INIT",
		"auth-init-princ",
		"Mechanism supports authentication of initiator to acceptor.",
		"1.3.6.1.5.5.13.10",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0a },
    },

	// 1.3.6.1.5.5.13.11
	{ GSS_MA_AUTH_TARG,
		"GSS_MA_AUTH_TARG",
		"auth-targ-princ",
		"Mechanism supports authentication of acceptor to initiator.",
		"1.3.6.1.5.5.13.11",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0b },
    },

	// 1.3.6.1.5.5.13.12
	{ GSS_MA_AUTH_INIT_INIT,
		"GSS_MA_AUTH_INIT_INIT",
		"auth-init-princ-initial",
		"Mechanism supports authentication of initiator using initial credentials.",
		"1.3.6.1.5.5.13.12",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0c },
    },

	// 1.3.6.1.5.5.13.13
	{ GSS_MA_AUTH_TARG_INIT,
		"GSS_MA_AUTH_TARG_INIT",
		"auth-target-princ-initial",
		"Mechanism supports authentication of acceptor using initial credentials.",
		"1.3.6.1.5.5.13.13",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0d },
    },

	// 1.3.6.1.5.5.13.14
	{ GSS_MA_AUTH_INIT_ANON,
		"GSS_MA_AUTH_INIT_ANON",
		"auth-init-princ-anon",
		"Mechanism supports GSS_C_NT_ANONYMOUS as an initiator name.",
		"1.3.6.1.5.5.13.14",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0e },
    },

	// 1.3.6.1.5.5.13.15
	{ GSS_MA_AUTH_TARG_ANON,
		"GSS_MA_AUTH_TARG_ANON",
		"auth-targ-princ-anon",
		"Mechanism supports GSS_C_NT_ANONYMOUS as an acceptor name.",
		"1.3.6.1.5.5.13.15",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x0f },
    },

	// 1.3.6.1.5.5.13.16
	{ GSS_MA_DELEG_CRED,
		"GSS_MA_DELEG_CRED",
		"deleg-cred",
		"Mechanism supports credential delegation.",
		"1.3.6.1.5.5.13.16",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x10 },
    },

	// 1.3.6.1.5.5.13.17
	{ GSS_MA_INTEG_PROT,
		"GSS_MA_INTEG_PROT",
		"integ-prot",
		"Mechanism supports per-message integrity protection.",
		"1.3.6.1.5.5.13.17",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x11 },
    },

	// 1.3.6.1.5.5.13.18
	{ GSS_MA_CONF_PROT,
		"GSS_MA_CONF_PROT",
		"conf-prot",
		"Mechanism supports per-message confidentiality protection.",
		"1.3.6.1.5.5.13.18",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x12 },
    },

	// 1.3.6.1.5.5.13.19
	{ GSS_MA_MIC,
		"GSS_MA_MIC",
		"mic",
		"Mechanism supports Message Integrity Code (MIC) tokens.",
		"1.3.6.1.5.5.13.19",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x13 },
    },

	// 1.3.6.1.5.5.13.20
	{ GSS_MA_WRAP,
		"GSS_MA_WRAP",
		"wrap",
		"Mechanism supports wrap tokens.",
		"1.3.6.1.5.5.13.20",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x14 },
    },

	// 1.3.6.1.5.5.13.21
	{ GSS_MA_PROT_READY,
		"GSS_MA_PROT_READY",
		"prot-ready",
		"Mechanism supports per-message proteciton prior to full context establishment.",
		"1.3.6.1.5.5.13.21",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x15 },
    },

	// 1.3.6.1.5.5.13.22
	{ GSS_MA_REPLAY_DET,
		"GSS_MA_REPLAY_DET",
		"replay-detection",
		"Mechanism supports replay detection.",
		"1.3.6.1.5.5.13.22",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x16 },
    },

	// 1.3.6.1.5.5.13.23
	{ GSS_MA_OOS_DET,
		"GSS_MA_OOS_DET",
		"oos-detection",
		"Mechanism supports out-of-sequence detection.",
		"1.3.6.1.5.5.13.23",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x17 },
    },

	// 1.3.6.1.5.5.13.24
	{ GSS_MA_CBINDINGS,
		"GSS_MA_CBINDINGS",
		"channel-bindings",
		"Mechanism supports channel bindings.",
		"1.3.6.1.5.5.13.24",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x18 },
    },

	// 1.3.6.1.5.5.13.25
	{ GSS_MA_PFS,
		"GSS_MA_PFS",
		"pfs",
		"Mechanism supports Perfect Forward Security.",
		"1.3.6.1.5.5.13.25",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x19 },
    },

	// 1.3.6.1.5.5.13.26
	{ GSS_MA_COMPRESS,
		"GSS_MA_COMPRESS",
		"compress",
		"Mechanism supports compression of data inputs to gss_wrap().",
		"1.3.6.1.5.5.13.26",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x1a },
    },

	// 1.3.6.1.5.5.13.27
	{ GSS_MA_CTX_TRANS,
		"GSS_MA_CTX_TRANS",
		"context-transfer",
		"Mechanism supports security context export/import.",
		"1.3.6.1.5.5.13.27",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x1b },
    },

	// 1.3.6.1.5.5.13.28
	{ GSS_MA_NEGOEX_AND_SPNEGO,
		"GSS_MA_NEGOEX_AND_SPNEGO",
		"negoex-only",
		"NegoEx mechanism should also be negotiable through SPNEGO.",
		"1.3.6.1.5.5.13.28",
		[]byte{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x0d, 0x1c },
    },

}

