package main

import (
	"fmt"
	"log"

	_ "github.com/golang-auth/go-gssapi/v3/c"

	gssapi "github.com/golang-auth/go-gssapi/v3/interface"
)

// Override at build time with :
//
//	-ldflags '-X main.libname=<library-name>'
var libname string = "GSSAPI-C"

var gss = gssapi.NewLibrary(libname)

func main() {
	name, err := gss.ImportName("foo", gssapi.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		log.Fatal(err)
	}

	s, _, err := name.Display()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name is: %s\n", s)
}
