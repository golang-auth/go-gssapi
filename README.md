# GSSAPI interace for Go

go-gssapi provides GSSAPI bindings for Go.

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/golang-auth/go-gssapi)
[![Git Workflow](https://img.shields.io/github/actions/workflow/status/golang-auth/go-gssapi/checks.yml?branch=dev
)](https://img.shields.io/github/actions/workflow/status/golang-auth/go-gssapi/checks.yml?branch=de)
[![Go Version](https://img.shields.io/badge/go%20version-%3E=1.24-61CFDD.svg?style=flat-square)](https://golang.org/)
[![GO Reference](https://pkg.go.dev/badge/mod/github.com/golang-auth/go-gssapi)](https://pkg.go.dev/mod/github.com/golang-auth/go-gssapi/v3)

# Overview
This repository contains the Golang GSSAPI bindings interface and
provider-independent support functions [described in the wiki](https://github.com/golang-auth/go-gssapi/wiki/Golang-GSSAPI-bindings-specification).  A GSSAPI
provider that implements the interface is required along with this package.

Versions prior to v3 of this repository contained a GSSAPI implementation that
used native Golang Kerberos and was not pluggable.  As of version 3, the
providers are separate to the interface.

At this time, a provider that [wraps the C bindings](https://github.com/golang-auth/go-gssapi-c) is available.  We feel that the native Go Kerberos implementation needs a reasonable amount of work for it to be production ready and so a native provider will come at a later stage.  Developers are recommended to use the C wrappers
at this stage.

## Installation

Include the interface and common functions from this package:

```go
go get github.com/golang-auth/go-gssapi/v3
```

.. and a provider, for example `go-gssapi-c`:
```go
go get github.com/golang-auth/go-gssapi-c
```

## Getting started

The interface and provider packages should be included in the application.  The
provider package does not need to supply any symbols to the app -- just loading
it is enough to have it register itself:

```go
package main

import (
    _ "github.com/golang-auth/go-gssapi-c"
    "github.com/golang-auth/go-gssapi/v3"
)

// the name that go-gssapi-c registers itself under
var gss = gssapi.MustNewProvider("github.com/golang-auth/go-gssapi-c")
```

## Example code

Examples in Go are available along with C and Java examples collected from the Internet
are available [in the gssapi-examples repo](https://github.com/golang-auth/gssapi-examples).

