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

var namesToOids = []struct {
	name    string
	oid     string
	altOids []string
}{

	// the alternate OIDs are the old (pre RFC) OID and incorrect OID shipped with Windows 2000
	// (see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/211417c4-11ef-46c0-a8fb-f178a51c2088)
	{"GSS_MECH_KRB5", "1.2.840.113554.1.2.2", []string{"1.3.6.1.5.2", "1.2.840.48018.1.2.2"}},
	{"GSS_MECH_IAKERB", "1.3.6.1.5.2.5", []string{}},
	{"GSS_MECH_SPNEGO", "1.3.6.1.5.5.2", []string{}},
	{"GSS_MECH_SPKM-1", "1.3.6.1.5.5.1.1", []string{}},
	{"GSS_MECH_SPKM-2", "1.3.6.1.5.5.1.2", []string{}},
	{"GSS_MECH_SPKM-3", "1.3.6.1.5.5.1.3", []string{}},
}

var codeTemplate = `// SPDX-License-Identifier: Apache-2.0

package gssapi

// GENERATED CODE: DO NOT EDIT

var mechs = []struct {
	id        gssMechImpl
	mech      string
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
			fh.Close()
		}
	}()

	var t = template.Must(template.New("code").Funcs(funcs).Parse(codeTemplate))

	if err := t.Execute(fh, params); err != nil {
		log.Fatal(err)
	}

	if *output != "" {
		fh.Close()
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
