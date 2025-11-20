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

// ORDER MATTERS - must be the same as names.go!
var namesToOids = []struct {
	name    string
	oid     string
	altOids []string
}{
	{"GSS_NT_HOSTBASED_SERVICE", "1.2.840.113554.1.2.1.4", []string{"1.3.6.1.5.6.2"}},
	{"GSS_NT_USER_NAME", "1.2.840.113554.1.2.1.1", []string{}},
	{"GSS_NT_MACHINE_UID_NAME", "1.2.840.113554.1.2.1.2", []string{}},
	{"GSS_NT_STRING_UID_NAME", "1.2.840.113554.1.2.1.3", []string{}},
	{"GSS_NT_ANONYMOUS", "1.3.6.1.5.6.3", []string{}},
	{"GSS_NO_OID", "", []string{}},
	{"GSS_NT_EXPORT_NAME", "1.3.6.1.5.6.4", []string{}},
	{"GSS_NO_NAME", "", []string{}},
	{"GSS_NT_COMPOSITE_EXPORT", "1.3.6.1.5.6.6", []string{}},
	{"GSS_KRB5_NT_PRINCIPAL_NAME", "1.2.840.113554.1.2.2.1", []string{"1.2.840.48018.1.2.2"}},
	{"GSS_KRB5_NT_ENTERPRISE_NAME", "1.2.840.113554.1.2.2.6", []string{}},
	{"GSS_KRB5_NT_X509_CERT", "1.2.840.113554.1.2.2.7", []string{}},
	{"GSS_SPKM_NT_USER_NAME", "1.2.840.113554.1.2.1.1", []string{}},
	{"GSS_SPKM_NT_MACHINE_UID_NAME", "1.2.840.113554.1.2.1.2", []string{}},
	{"GSS_SPKM_NT_STRING_UID_NAME", "1.2.840.113554.1.2.1.3", []string{}},
}

var codeTemplate = `// SPDX-License-Identifier: Apache-2.0

package gssapi

// GENERATED CODE: DO NOT EDIT

var nameTypes = []struct {
	id        gssNameTypeImpl
	name      string
	oidString string
	oid       Oid
	altOids   []Oid
}{
	
{{range .}}
	// {{.Oid.S}}
	{ {{.Name}},
		"{{.Name}}",
		"{{.Oid.S}}",
		{{ $length := len .Oid.B }} {{- if gt $length 0}}[]byte{ {{bytesFormat .Oid.B}} } {{- else}}nil{{- end}},
		[]Oid{ {{- range .AltOids}}
		   { {{- bytesFormat .B}} }, // {{ .S }}
		 {{ end}} }},
{{end}}
}

`

type oid struct {
	S string
	B []byte
}

type tmplParam struct {
	Name    string
	Oid     oid
	AltOids []oid
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
	params := make([]tmplParam, len(namesToOids))

	// marshal the OIDs to DER encoding..
	for i, entry := range namesToOids {
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
			Name: entry.name,
			Oid:  oid{S: entry.oid, B: enc},
		}

		for _, alt := range entry.altOids {
			objId := stringToOid(alt)
			enc, err := asn1.Marshal(objId)
			if err != nil {
				panic(fmt.Errorf("parsing %s: %w", objId, err))
			}

			params[i].AltOids = append(params[i].AltOids, oid{S: alt, B: enc[2:]})
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
