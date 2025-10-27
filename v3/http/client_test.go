package http

import (
	"fmt"
	"log"

	"github.com/golang-auth/go-gssapi/v3"
)

func ExampleClient() {
	p := gssapi.MustNewProvider("github.com/golang-auth/go-gssapi-c")

	client := NewClient(p)
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)

	// Output:
	// 200 OK
}
