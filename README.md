# GSSAPI interace for Go

go-gssapi provides GSSAPI bindings for Go.

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/golang-auth/go-gssapi)
[![Git Workflow](https://img.shields.io/github/actions/workflow/status/golang-auth/go-gssapi/checks.yml?branch=dev
)](https://img.shields.io/github/actions/workflow/status/golang-auth/go-gssapi/checks.yml?branch=de)
[![Go Version](https://img.shields.io/badge/go%20version-%3E=1.24-61CFDD.svg?style=flat-square)](https://golang.org/)
[![GO Reference](https://pkg.go.dev/badge/mod/github.com/golang-auth/go-gssapi)](https://pkg.go.dev/mod/github.com/golang-auth/go-gssapi/v3)

# Overview

This repository contains the Golang GSSAPI bindings interface,
provider-independent support functions [described in the wiki][go-gssapi-spec] and
an HTTTP library providing Negotiate authentication.  A GSSAPI
provider that implements the interface is required along with this package.

Versions prior to v3 of this repository contained a GSSAPI implementation that
used native Golang Kerberos and was not pluggable.  As of version 3, the
providers are separate to the interface.

At this time, a provider that [wraps the C bindings][gssapi-c]] is available.  We feel that the
native Go Kerberos implementation needs a reasonable amount of work for it to be production ready
and so a native provider will come at a later stage.  Developers are recommended to use the C wrappers
at this stage.


## Status of the project

The code is currently in beta, and we're inviting users to try out the interfaces and provide feedback.
While the API may undergo minor changes before the final v3.0.0 release, we do not anticipate significant
modifications. Developers adopting the library now should expect minimal adjustments when updating to the
final v3.0.0 version.


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

## Initiator context establishment

The client (initiator) must call `InitSecContext` to create the security context and then exchange
tokens with its peer (the acceptor) until a security context is established.  The initiator
produces the first token of the exchange and continues the process until its half of the
context is established:

```go
peerName, err := gss.ImportName("ldap@someserver.example.com",  gssapi.GSS_NT_HOSTBASED_SERVICE)
...
defer peerName.Release()

flags := gssapi.ContextFlagMutual
secctx, err := gss.InitSecContext(peerName, opgssapi.WithInitiatorFlags(flags))
...
defer secctx.Delete()

var inToken []byte

for secctx.ContinueNeeded() {
    outToken, info, err := secctx.Continue(inToken)
    // always send a non-empty token to the peer
    if len(outToken) > 0 {
        sendToken(outToken)
    }
    // result was not GSS_S_COMPLETE or GSS_S_CONTINUE_NEEDED
    if err != nil {
        break
    }

    // read a token from the peer if the initator context isn't established yet
    if secctx.ContinueNeeded() {
       inToken = recvToken()
    }
}
```

## Acceptor context establishment

The server (acceptor) must call `AcceptSecContext` to create its security context and then
exchange tokens with its peer (the initiator) until its secuity context is established.  The
acceptor must first receive a token from the peer as the initiator creates the first token:

```go
secctx, err := gss.AcceptSecContext()
if err != nil {
    return showErr(err)
}

defer secctx.Delete()

for secctx.ContinueNeeded() {
    inToken := recvToken()

    outToken, info, err := secctx.Continue(inToken)
    if len(outToken) > 0 {
        sendToken(outToken)
    }
    if err != nil {
        break
    }
}
```

## Post establishment

After the security context is fully established, the peers can exchange application data protected
by the context.  The [GetMIC] and [VerifyMIC] methods can be used to generate a and validate message integrity tokens that are communicated separately to the plaintext application data.
[Wrap] and [Unwrap] can be used to generate GSSAPI messages that include the application data
incorporated with signing and/or encryption depending on the context flags that were requested
and negotiated.


## HTTP Negotiate

A GSSAPI enabled [http-client] is provided in [http][gssapi-http].

## Example code

Examples in Go are available along with C and Java examples collected from the Internet
are available [in the gssapi-examples repo](https://github.com/golang-auth/gssapi-examples).

[http-client]: https://pkg.go.dev/net/http#Client
[gssapi-http]: ./http
[gssapi-c]: https://github.com/golang-auth/go-gssapi-c
[go-gssapi-spec]: https://github.com/golang-auth/go-gssapi/wiki/Golang-GSSAPI-bindings-specification
[rfc7546]: https://datatracker.ietf.org/doc/html/rfc7546