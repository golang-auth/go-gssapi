package gssapi

import g "github.com/golang-auth/go-gssapi/v3/interface"

const LIBID = "GSSAPI-C"

func init() {
	g.RegisterLibrary(LIBID, New)
}

type library struct {
	name string
}

func New() g.Library {
	return &library{
		name: LIBID,
	}
}
