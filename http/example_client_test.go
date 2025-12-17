package http_test

import (
	"fmt"
	"log"

	"github.com/golang-auth/go-gssapi/v3"
	ghttp "github.com/golang-auth/go-gssapi/v3/http"
)

var GssProvider = "github.com/golang-auth/go-gssapi-c"

func ExampleNewClient() {
	p, err := gssapi.NewProvider(GssProvider)
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}

	opts := []ghttp.ClientOption{
		ghttp.WithInitiatorMutual(),
	}

	client, err := ghttp.NewClient(p, nil, opts...)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	resp, err := client.Get("http://localhost:1234/")
	if err != nil {
		log.Fatalf("Failed to get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Println(resp.Status)
}
