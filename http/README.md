# GSSAPI enabled HTTP Client

The `http` package provides a GSSAPI-enabled HTTP client for Go applications.

[![Go Version](https://img.shields.io/badge/go%20version-%3E=1.24-61CFDD.svg?style=flat-square)](https://golang.org/)
[![GO Reference](https://pkg.go.dev/badge/mod/github.com/golang-auth/go-gssapi)][godoc]

## Overview

The package provides a RoundTripper that adds GSSAPI authentication support as defined
in [RFC 4559][rfc4559].


## Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/golang-auth/go-gssapi/v3"
    "github.com/golang-auth/go-gssapi/v3/http"
)

func main() {
    p := gssapi.MustNewProvider("github.com/golang-auth/go-gssapi-c")
    
    client := http.NewClient(p, nil)
    resp, err := client.Get("https://example.com")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
    
    fmt.Println(resp.Status)
}
```


See the [GoDoc reference][godoc] for more detailed usage information.


[godoc]: https://pkg.go.dev/mod/github.com/golang-auth/go-gssapi/v3/http
[rfc4559]: https://datatracker.ietf.org/doc/html/rfc4559
