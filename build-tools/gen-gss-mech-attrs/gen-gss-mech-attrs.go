// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"text/template"
)

// RFC 5587 Mechanism attributes
var attrsToOids = []struct {
	name      string
	shortDesc string
	longDesc  string
	oid       string
}{
	{
		"GSS_MA_MECH_CONCRETE",
		"concrete-mech",
		"Mechanism is neither a pseudo-mechanism nor a composite mechanism.",
		"1.3.6.1.5.5.13.1",
	},
	{
		"GSS_MA_MECH_PSEUDO",
		"pseudo-mech",
		"Mechanism is a pseudo-mechanism.",
		"1.3.6.1.5.5.13.2",
	},
	{
		"GSS_MA_MECH_COMPOSITE",
		"composite-mech",
		"Mechanism is a composite of other mechanisms.",
		"1.3.6.1.5.5.13.3",
	},
	{
		"GSS_MA_MECH_NEGO",
		"mech-negotiation-mech",
		"Mechanism negotiates other mechanisms.",
		"1.3.6.1.5.5.13.4",
	},
	{
		"GSS_MA_MECH_GLUE",
		"mech-glue",
		"OID is not a mechanism but the GSS-API itself.",
		"1.3.6.1.5.5.13.5",
	},
	{
		"GSS_MA_NOT_MECH",
		"not-mech",
		"Known OID but not a mechanism OID.",
		"1.3.6.1.5.5.13.6",
	},
	{
		"GSS_MA_DEPRECATED",
		"mech-deprecated",
		"Mechanism is deprecated.",
		"1.3.6.1.5.5.13.7",
	},
	{
		"GSS_MA_NOT_DFLT_MECH",
		"mech-not-default",
		"Mechanism must not be used as a default mechanism.",
		"1.3.6.1.5.5.13.8",
	},
	{
		"GSS_MA_ITOK_FRAMED",
		"initial-is-framed",
		"Mechanism's initial contexts are properly framed.",
		"1.3.6.1.5.5.13.9",
	},
	{
		"GSS_MA_AUTH_INIT",
		"auth-init-princ",
		"Mechanism supports authentication of initiator to acceptor.",
		"1.3.6.1.5.5.13.10",
	},
	{
		"GSS_MA_AUTH_TARG",
		"auth-targ-princ",
		"Mechanism supports authentication of acceptor to initiator.",
		"1.3.6.1.5.5.13.11",
	},
	{
		"GSS_MA_AUTH_INIT_INIT",
		"auth-init-princ-initial",
		"Mechanism supports authentication of initiator using initial credentials.",
		"1.3.6.1.5.5.13.12",
	},
	{
		"GSS_MA_AUTH_TARG_INIT",
		"auth-target-princ-initial",
		"Mechanism supports authentication of acceptor using initial credentials.",
		"1.3.6.1.5.5.13.13",
	},
	{
		"GSS_MA_AUTH_INIT_ANON",
		"auth-init-princ-anon",
		"Mechanism supports GSS_C_NT_ANONYMOUS as an initiator name.",
		"1.3.6.1.5.5.13.14",
	},
	{
		"GSS_MA_AUTH_TARG_ANON",
		"auth-targ-princ-anon",
		"Mechanism supports GSS_C_NT_ANONYMOUS as an acceptor name.",
		"1.3.6.1.5.5.13.15",
	},
	{
		"GSS_MA_DELEG_CRED",
		"deleg-cred",
		"Mechanism supports credential delegation.",
		"1.3.6.1.5.5.13.16",
	},
	{
		"GSS_MA_INTEG_PROT",
		"integ-prot",
		"Mechanism supports per-message integrity protection.",
		"1.3.6.1.5.5.13.17",
	},
	{
		"GSS_MA_CONF_PROT",
		"conf-prot",
		"Mechanism supports per-message confidentiality protection.",
		"1.3.6.1.5.5.13.18",
	},
	{
		"GSS_MA_MIC",
		"mic",
		"Mechanism supports Message Integrity Code (MIC) tokens.",
		"1.3.6.1.5.5.13.19",
	},
	{
		"GSS_MA_WRAP",
		"wrap",
		"Mechanism supports wrap tokens.",
		"1.3.6.1.5.5.13.20",
	},
	{
		"GSS_MA_PROT_READY",
		"prot-ready",
		"Mechanism supports per-message proteciton prior to full context establishment.",
		"1.3.6.1.5.5.13.21",
	},
	{
		"GSS_MA_REPLAY_DET",
		"replay-detection",
		"Mechanism supports replay detection.",
		"1.3.6.1.5.5.13.22",
	},
	{
		"GSS_MA_OOS_DET",
		"oos-detection",
		"Mechanism supports out-of-sequence detection.",
		"1.3.6.1.5.5.13.23",
	},
	{
		"GSS_MA_CBINDINGS",
		"channel-bindings",
		"Mechanism supports channel bindings.",
		"1.3.6.1.5.5.13.24",
	},
	{
		"GSS_MA_PFS",
		"pfs",
		"Mechanism supports Perfect Forward Security.",
		"1.3.6.1.5.5.13.25",
	},
	{
		"GSS_MA_COMPRESS",
		"compress",
		"Mechanism supports compression of data inputs to gss_wrap().",
		"1.3.6.1.5.5.13.26",
	},
	{
		"GSS_MA_CTX_TRANS",
		"context-transfer",
		"Mechanism supports security context export/import.",
		"1.3.6.1.5.5.13.27",
	},
	{
		"GSS_MA_NEGOEX_AND_SPNEGO",
		"negoex-only",
		"NegoEx mechanism should also be negotiable through SPNEGO.",
		"1.3.6.1.5.5.13.28",
	},
}

var codeTemplate = `// SPDX-License-Identifier: Apache-2.0

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

{{range .}}
	// {{.Oid.S}}
	{ {{.Name}},
		"{{.Name}}",
		"{{.ShortDesc}}",
		"{{.LongDesc}}",
		"{{.Oid.S}}",
		{{ $length := len .Oid.B }} {{- if gt $length 0}}[]byte{ {{bytesFormat .Oid.B}} } {{- else}}nil{{- end}},
    },
{{end}}
}

`

type oid struct {
	S string
	B []byte
}

type tmplParam struct {
	Name      string
	ShortDesc string
	LongDesc  string
	Oid       oid
}

func main() {
	output := flag.String("o", "", "output file name")
	flag.Parse()

	params := makeParams()

	funcs := template.FuncMap{
		"bytesFormat": bytesFormat,
	}

	fh := os.Stdout
	var err error
	if *output != "" {
		fh, err = os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer func() {
		if *output != "" {
			_ = fh.Close()
		}
	}()

	var t = template.Must(template.New("code").Funcs(funcs).Parse(codeTemplate))

	if err := t.Execute(fh, params); err != nil {
		log.Fatal(err)
	}

	if *output != "" {
		_ = fh.Close()
	}
}

func makeParams() []tmplParam {
	params := make([]tmplParam, len(attrsToOids))

	// marshal the OIDs to DER encoding..
	for i, entry := range attrsToOids {
		var enc []byte
		var err error
		if entry.oid != "" {
			objId := stringToOid(entry.oid)
			enc, err = asn1.Marshal(objId)

			if err != nil {
				panic(fmt.Errorf("parsing %s: %w", objId, err))
			}

			enc = enc[2:]
		}

		params[i] = tmplParam{
			Name:      entry.name,
			ShortDesc: entry.shortDesc,
			LongDesc:  entry.longDesc,
			Oid:       oid{S: entry.oid, B: enc},
		}
	}

	return params
}

func bytesFormat(b []byte) string {
	strs := make([]string, len(b))
	for i, s := range b {
		strs[i] = fmt.Sprintf("0x%02x", s)
	}
	return strings.Join(strs, ", ")
}

func stringToOid(s string) asn1.ObjectIdentifier {
	// split string into components
	elms := strings.Split(s, ".")

	oid := make(asn1.ObjectIdentifier, len(elms))

	for i, elm := range elms {
		j, err := strconv.ParseUint(elm, 10, 32)
		if err != nil {
			panic(err)
		}

		oid[i] = int(j)
	}

	return oid
}
