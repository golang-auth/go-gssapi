package http_test

import (
	"fmt"
	"html"
	"log"
	"net/http"

	"github.com/golang-auth/go-gssapi/v3"
	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

var KeyFile = "testdata/server.key"
var CertFile = "testdata/server.crt"

func testHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}

func ExampleWithAcceptorChannelBindingDisposition() {
	p, err := gssapi.NewProvider(GssProvider)
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}

	opts := []ghttp.HandlerOption{
		ghttp.WithAcceptorChannelBindingDisposition(ghttp.ChannelBindingDispositionRequire),
	}

	handler, err := ghttp.NewHandler(p, http.HandlerFunc(testHandler), opts...)
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}

	server := ghttp.ServerWithStashConn(&http.Server{
		Addr:    ":1234",
		Handler: handler,
	})

	log.Fatal(server.ListenAndServeTLS(CertFile, KeyFile))
}
