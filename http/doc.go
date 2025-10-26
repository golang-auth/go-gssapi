// SPDX-License-Identifier: Apache-2.0

/*
Package http provides GSSAPI (Negotiate) enabled HTTP client and server
implementations supporting RFC 4559.

	import (
		net/http
		ghttp "github.com/golang-auth/go-gssapi/v3/http"
		_ "github.com/golang-auth/go-gssapi-c"
	)

	p, err := gssapi.NewProvider("github.com/golang-auth/go-gssapi-c")
	...

# Clients and transorts

Create a client to use a default GSSAPI enabled transport. The client can be
used anywhere a standard [http.Client] can be used.

	client, err := ghttp.NewClient(p, nil)
	...

	resp, err := client.Get("https://example.com")
	...

	req, err := http.NewRequest("GET", "http://example.com", nil)
	...
	req.Header.Add("If-None-Match", `W/"wyzzy"`)
	resp, err := client.Do(req)
	...

To control GSSAPI parameters, create a transport:

	transport := ghttp.NewTransport(
		p,
		http.WithOpportunistic(),
		http.WithCredential(cred),
	)
	client := http.Client{Transport: transport}
	resp, err := client.Get("https://example.com")

The GSSAPI enabled transport wraps a standard [http.RoundTripper]. By default
it uses [http.DefaultTransport]. A custom round-tripper can be provided to the
transport using [WithRoundTripper].

# Request body handling

For HTTP methods such as POST, PUT, and others that include a request body, the
client must send the full body to the server regardless of the server’s
response code.

Starting with Go 1.8, the http.Request.GetBody method enables supported request
body types to be rewound and resent if the server responds with a 401
Unauthorized challenge.

However, for large request bodies, retransmission can be inefficient.

One way to avoid sending large bodies multiple times is to use the Expect:
100-continue header.

Normal flow:
  - The client sends headers first.
  - If the server responds with 100 Continue, the client sends the body.
  - If the server responds with 401 Unauthorized (or any final status) before
    sending 100 Continue, the client does not send the body.

This approach saves bandwidth when the request is likely to be challenged, but
it depends on correct server implementation of 100-continue semantics.

Why this matters:

  - Under HTTP/1.1 (RFC 9110, §9), if the client sends a request with a
    Content-Length header and no Expect: 100-continue, then the server must
    either read and discard the entire body, or close the connection after
    sending the response.

  - This ensures leftover body bytes do not corrupt the interpretation of the
    next request over the same connection.

With Expect: 100-continue:

  - The body is not sent until the server signals 100 Continue.
  - If the server rejects early, there are no unread body bytes and the
    connection protocol stays clean without draining.

Client behavior:

  - Support for Expect: 100-continue is disabled by default due to
    implementation concerns with some servers.

  - It can be enabled by setting a threshold (in bytes) greater than zero.

    When enabled, the client will add the header to requests that:

  - Do not have opportunistic authentication enabled, and

  - Either have a body size exceeding the threshold, or have a body that is not
    rewindable via GetBody.

  - The optimal threshold depends on factors such as network bandwidth, MTU,
    TLS overhead, and server 100-continue reliability.

The Go [net/http] server forces the connection to close after the reply when
the client requests a 100-continue response.

  - RFC view: If Content-Length is set, the client must send the full body,
    even without 100 Continue.
  - Practical view: Closing avoids reading (and discarding) large unused bodies
    and prevents ambiguity in the TCP stream.
  - Impact: When rejecting requests early (for example, 401 Unauthorized), the
    connection will close, requiring a new one for the retry.

For large request bodies and Negotiate authentication, this is generally
preferable to draining the body.

# Opportunistic authentication

The GSSAPI enabled transport supports opportunistic authentication as described
in RFC 4559 § 4.2 . The client does not wait for the server to respond with a
401 status code before sending an authentication token. This optimization can
reduce round trips between the client and server, at the cost of initializing
the GSSAPI context and potentially exposing authentication credentials to the
server unnecessarily.

# Servers

[Handler] is a [http.Handler] that performs GSSAPI authentication and then calls
the next handler with the initiator name in the request context.

Use Negotiate authentication for a subset of paths:

	// Use Negotiate authentication for the /foo path
	http.Handle("/foo", ghttp.NewHandler(p, fooHandler))

	// but not for /bar
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

Use Negotiate authentication for all paths:

	h := ghttp.NewHandler(p, http.DefaultServeMux)
	log.Fatal(http.ListenAndServe(":8080", h))
*/
package http
