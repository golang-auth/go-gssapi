package gssapi

import "os"

//go:generate  ../build-tools/mk-test-vectors -o testvecs_test.go

type saveVars struct {
	vars map[string]string
}

func newSaveVars(varNames ...string) saveVars {
	sv := saveVars{
		vars: make(map[string]string),
	}

	for _, varName := range varNames {
		sv.vars[varName] = os.Getenv(varName)
	}

	return sv
}

func (sv saveVars) Restore() {
	for varName, varVal := range sv.vars {
		if varVal == "" {
			os.Unsetenv(varName)
		} else {
			os.Setenv(varName, varVal)
		}
	}
}
